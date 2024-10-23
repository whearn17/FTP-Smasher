from dataclasses import dataclass
from datetime import datetime
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Dict
from ftplib import FTP, all_errors
import re
from pathlib import PurePosixPath

from .config import ScannerConfig
from .utils.file_utils import read_ips
from .models import Database

@dataclass
class FTPFileInfo:
    """Represents information about a file or directory from FTP LIST command"""
    name: str
    permissions: Optional[str] = None
    size: Optional[int] = None
    modified: Optional[datetime] = None
    is_dir: bool = False

    @classmethod
    def from_list_output(cls, line: str) -> 'FTPFileInfo':
        """Create FTPFileInfo from FTP LIST command output line"""
        parts = line.split(maxsplit=8)
        if len(parts) < 9:
            return cls(name=line)

        try:
            modified = datetime.strptime(f"{parts[5]} {parts[6]} {parts[7]}", "%b %d %Y")
        except ValueError:
            modified = None

        try:
            size = int(parts[4])
        except ValueError:
            size = None

        return cls(
            name=parts[8],
            permissions=parts[0],
            size=size,
            modified=modified,
            is_dir=parts[0].startswith('d')
        )

class FTPConnection:
    """Handles FTP connection and basic operations"""
    def __init__(self, host: str, timeout: int):
        self.host = host
        self.timeout = timeout
        self.ftp: Optional[FTP] = None
        self._logger = logging.getLogger(f'{__name__}.FTPConnection')

    def __enter__(self) -> 'FTPConnection':
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def connect(self) -> None:
        """Establish FTP connection and perform anonymous login"""
        self._logger.debug(f"Connecting to {self.host}")
        self.ftp = FTP(self.host, timeout=self.timeout)
        self.ftp.login("anonymous", "anonymous@example.com")
        self._logger.info(f"Connected to {self.host}")

    def disconnect(self) -> None:
        """Close FTP connection if active"""
        if self.ftp:
            self.ftp.quit()
            self.ftp = None
            self._logger.debug(f"Disconnected from {self.host}")

    def get_server_info(self) -> tuple[Optional[str], Optional[str]]:
        """Extract server type and version from welcome message"""
        if not self.ftp:
            return None, None

        welcome = self.ftp.getwelcome()
        if not welcome:
            return None, None

        match = re.search(r'([A-Za-z]+) FTP[D]? .*?([0-9.]+)', welcome)
        if not match:
            return None, None

        return match.group(1), match.group(2)

    def list_directory(self, path: str) -> List[FTPFileInfo]:
        """Get directory listing as FTPFileInfo objects"""
        if not self.ftp:
            return []

        file_list = []
        self.ftp.retrlines('LIST', file_list.append)
        return [FTPFileInfo.from_list_output(line) for line in file_list]

    def change_directory(self, path: str) -> bool:
        """Change current directory, return success status"""
        if not self.ftp:
            return False

        try:
            self.ftp.cwd(path)
            return True
        except all_errors:
            return False

class FTPScanner:
    """Main FTP scanning functionality"""
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = self._setup_logger()
        self.db = Database()
        self.servers_found: List[str] = []

    @staticmethod
    def _setup_logger() -> logging.Logger:
        """Configure and return logger instance"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(thread)d - %(message)s',
            handlers=[
                logging.FileHandler('ftp_scanner.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger('FTPScanner')

    def _process_directory_contents(
        self,
        connection: FTPConnection,
        path: str,
        server_id: int,
        dir_id: int
    ) -> None:
        """Process contents of a directory, handling files and subdirectories"""
        contents = connection.list_directory(path)
        
        file_count = sum(1 for item in contents if not item.is_dir)
        dir_count = sum(1 for item in contents if item.is_dir and item.name not in {'.', '..'})
        
        self.logger.info(f"Found {file_count} files and {dir_count} subdirectories in {path}")

        for item in contents:
            if item.is_dir and item.name not in {'.', '..'}:
                new_path = str(PurePosixPath(path) / item.name)
                self.scan_directory(connection, new_path, server_id)
            elif not item.is_dir:
                self.db.add_file(
                    dir_id,
                    item.name,
                    item.size,
                    item.modified,
                    item.permissions
                )

    def scan_directory(
        self,
        connection: FTPConnection,
        path: str,
        server_id: int
    ) -> None:
        """Recursively scan an FTP directory"""
        try:
            self.logger.info(f"Scanning directory: {path}")
            
            if not connection.change_directory(path):
                self.logger.error(f"Failed to access directory: {path}")
                return

            dir_id = self.db.add_directory(server_id, path)
            self._process_directory_contents(connection, path, server_id, dir_id)

        except Exception as e:
            self.logger.error(f"Error scanning directory {path}: {str(e)}", exc_info=True)
        finally:
            connection.change_directory('..')

    def scan_server(self, ip: str) -> Optional[str]:
        """Scan a single FTP server"""
        self.logger.info(f"Starting scan of server: {ip}")
        
        try:
            with FTPConnection(ip, self.config.timeout) as connection:
                server_type, version = connection.get_server_info()
                
                if server_type and version:
                    self.logger.info(f"Detected server {ip}: {server_type} {version}")
                
                server_id = self.db.add_server(ip, "success", server_type, version)
                self.scan_directory(connection, "/", server_id)
                
                self.logger.info(f"Completed scan of server: {ip}")
                return ip

        except all_errors as e:
            self.logger.warning(f"Failed to connect to {ip}: {str(e)}")
            self.db.add_server(ip, "failed")
        except Exception as e:
            self.logger.error(f"Error scanning {ip}: {str(e)}", exc_info=True)
            self.db.add_server(ip, "error")
        
        return None

    def scan(self, ip_file: str) -> List[str]:
        """Perform scanning of multiple servers using thread pool"""
        self.logger.info(f"Starting scan with input file: {ip_file}")
        
        try:
            ip_list = read_ips(ip_file)
            if not ip_list:
                self.logger.error("No valid IPs found in input file")
                return []

            self.logger.info(f"Scanning {len(ip_list)} IPs using {self.config.num_threads} threads")

            with ThreadPoolExecutor(max_workers=self.config.num_threads) as executor:
                results = list(executor.map(self.scan_server, ip_list))
                self.servers_found = [ip for ip in results if ip is not None]

            self.logger.info(
                f"Scan complete: {len(self.servers_found)}/{len(ip_list)} servers successful"
            )
            return self.servers_found

        except Exception as e:
            self.logger.error(f"Scanner error: {str(e)}", exc_info=True)
            return []

    def get_statistics(self) -> Dict[str, any]:
        """Retrieve scanning statistics from database"""
        stats = self.db.get_statistics()
        self.logger.info(
            f"Scan statistics: {stats['successful_servers']}/{stats['total_servers']} servers, "
            f"{stats['total_directories']} directories, {stats['total_files']} files, "
            f"total size: {stats['total_size']} bytes"
        )
        return stats