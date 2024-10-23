import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Dict
from ftplib import FTP, all_errors
from datetime import datetime
import re
from pathlib import PurePosixPath

from .config import ScannerConfig
from .utils.file_utils import read_ips
from .models import Database

class FTPFileInfo:
    def __init__(self, line: str):
        """Parse an FTP LIST command output line"""
        parts = line.split(maxsplit=8)
        if len(parts) >= 9:
            self.permissions = parts[0]
            try:
                self.size = int(parts[4])
            except ValueError:
                self.size = None
            # Parse date
            date_str = f"{parts[5]} {parts[6]} {parts[7]}"
            try:
                self.modified = datetime.strptime(date_str, "%b %d %Y")
            except ValueError:
                self.modified = None
            self.name = parts[8]
            self.is_dir = self.permissions.startswith('d')
        else:
            self.permissions = None
            self.size = None
            self.modified = None
            self.name = line
            self.is_dir = False

class FTPScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.db = Database()
        self.servers_found = []
        
    @staticmethod
    def _setup_logging():
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ftp_scanner.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger('FTPScanner')

    def scan_directory(self, ftp: FTP, path: str, server_id: int) -> None:
        """Recursively scan an FTP directory"""
        try:
            # Change to directory
            ftp.cwd(path)
            
            # Add directory to database
            dir_id = self.db.add_directory(server_id, path)
            
            # Get directory listing
            file_list = []
            ftp.retrlines('LIST', file_list.append)
            
            # Process each entry
            for line in file_list:
                file_info = FTPFileInfo(line)
                
                if file_info.is_dir and file_info.name not in {'.', '..'}:
                    # Recursively scan subdirectory
                    new_path = str(PurePosixPath(path) / file_info.name)
                    self.scan_directory(ftp, new_path, server_id)
                elif not file_info.is_dir:
                    # Add file to database
                    self.db.add_file(dir_id, file_info.name, file_info.size,
                                   file_info.modified, file_info.permissions)
                    
        except all_errors as e:
            self.logger.error(f"Error scanning directory {path}: {str(e)}")
        finally:
            # Return to parent directory
            ftp.cwd('..')

    def scan_server(self, ip: str) -> Optional[str]:
        """Scan an FTP server and store results in database"""
        try:
            with FTP(ip, timeout=self.config.timeout) as ftp:
                # Login
                ftp.login("anonymous", "anonymous@example.com")
                
                # Get server info
                welcome = ftp.getwelcome()
                server_type = None
                version = None
                
                # Try to parse server type and version from welcome message
                if welcome:
                    match = re.search(r'([A-Za-z]+) FTP[D]? .*?([0-9.]+)', welcome)
                    if match:
                        server_type = match.group(1)
                        version = match.group(2)
                
                # Add server to database
                server_id = self.db.add_server(ip, "success", server_type, version)
                
                # Start recursive scan from root
                self.scan_directory(ftp, "/", server_id)
                
                self.logger.info(f"Successfully scanned {ip}")
                return ip
                
        except all_errors as e:
            self.logger.debug(f"Failed to connect to {ip}: {str(e)}")
            self.db.add_server(ip, "failed")
        except Exception as e:
            self.logger.error(f"Unexpected error scanning {ip}: {str(e)}")
            self.db.add_server(ip, "error")
        
        return None

    def scan(self, ip_file: str) -> List[str]:
        """Main scanning method using only threading"""
        try:
            # Read and validate IP list
            ip_list = read_ips(ip_file)
            if not ip_list:
                self.logger.error("No valid IPs found in input file")
                return []

            # Use thread pool for scanning
            with ThreadPoolExecutor(max_workers=self.config.num_threads) as executor:
                # Map each IP to a thread
                results = list(executor.map(self.scan_server, ip_list))
                
                # Collect successful results
                self.servers_found = [ip for ip in results if ip is not None]
            
            return self.servers_found
            
        except Exception as e:
            self.logger.error(f"Scanner error: {str(e)}")
            return []

    def get_statistics(self) -> Dict[str, any]:
        """Get scanning statistics"""
        return self.db.get_statistics()