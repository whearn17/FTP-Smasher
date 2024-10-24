import sqlite3
from datetime import datetime
from typing import Optional
from contextlib import contextmanager
import threading


class Database:
    _local = threading.local()

    def __init__(self, db_path: str = "ftp_scan.db"):
        self.db_path = db_path
        # Initialize the main connection for schema creation
        with self.get_connection() as conn:
            with conn:  # This ensures proper transaction handling
                self.init_db(conn)

    @contextmanager
    def get_connection(self):
        """Get a thread-local database connection"""
        # Check if this thread already has a connection
        if not hasattr(self._local, 'connection'):
            # Create a new connection for this thread
            self._local.connection = sqlite3.connect(self.db_path)
            self._local.connection.row_factory = sqlite3.Row

        try:
            yield self._local.connection
        except Exception as e:
            raise e

    def init_db(self, conn):
        """Initialize database tables"""
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL UNIQUE,
                last_scan TIMESTAMP,
                status TEXT,
                type TEXT,
                version TEXT
            );

            CREATE TABLE IF NOT EXISTS directories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER,
                path TEXT NOT NULL,
                last_scan TIMESTAMP,
                FOREIGN KEY (server_id) REFERENCES servers(id),
                UNIQUE(server_id, path)
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                directory_id INTEGER,
                name TEXT NOT NULL,
                size INTEGER,
                modified TIMESTAMP,
                permissions TEXT,
                FOREIGN KEY (directory_id) REFERENCES directories(id)
            );
        """)

    def add_server(self, host: str, status: str, server_type: str = None, version: str = None) -> int:
        """Add or update a server and return its ID"""
        with self.get_connection() as conn:
            with conn:  # Handle transaction automatically
                cursor = conn.execute("""
                    INSERT INTO servers (host, last_scan, status, type, version)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(host) DO UPDATE SET
                        last_scan=excluded.last_scan,
                        status=excluded.status,
                        type=excluded.type,
                        version=excluded.version
                    RETURNING id
                    """, (host, datetime.now(), status, server_type, version))
                row = cursor.fetchone()
                server_id = row[0]
                cursor.close()
                return server_id

    def add_directory(self, server_id: int, path: str) -> int:
        """Add or update a directory and return its ID"""
        with self.get_connection() as conn:
            with conn:  # Handle transaction automatically
                cursor = conn.execute("""
                    INSERT INTO directories (server_id, path, last_scan)
                    VALUES (?, ?, ?)
                    ON CONFLICT(server_id, path) DO UPDATE SET
                        last_scan=excluded.last_scan
                    RETURNING id
                    """, (server_id, path, datetime.now()))
                row = cursor.fetchone()
                dir_id = row[0]
                cursor.close()
                return dir_id

    def add_file(self, directory_id: int, name: str, size: Optional[int],
                 modified: Optional[datetime], permissions: Optional[str]):
        """Add a file to the database"""
        with self.get_connection() as conn:
            with conn:  # Handle transaction automatically
                cursor = conn.execute("""
                    INSERT INTO files (directory_id, name, size, modified, permissions)
                    VALUES (?, ?, ?, ?, ?)
                    """, (directory_id, name, size, modified, permissions))
                cursor.close()

    def generate_scan_summary_statistics(self) -> dict:
        """Get scanning statistics from the database"""
        with self.get_connection() as conn:
            stats = {}
            with conn:  # Handle transaction automatically
                # Execute each query separately and close cursor
                cursor = conn.execute('SELECT COUNT(*) FROM servers')
                stats['total_servers'] = cursor.fetchone()[0]
                cursor.close()

                cursor = conn.execute(
                    'SELECT COUNT(*) FROM servers WHERE status = "success"')
                stats['successful_servers'] = cursor.fetchone()[0]
                cursor.close()

                cursor = conn.execute('SELECT COUNT(*) FROM directories')
                stats['total_directories'] = cursor.fetchone()[0]
                cursor.close()

                cursor = conn.execute('SELECT COUNT(*) FROM files')
                stats['total_files'] = cursor.fetchone()[0]
                cursor.close()

                cursor = conn.execute('SELECT SUM(size) FROM files')
                stats['total_size'] = cursor.fetchone()[0] or 0
                cursor.close()

            return stats

    def close(self):
        """Close the database connection for this thread"""
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
            delattr(self._local, 'connection')
