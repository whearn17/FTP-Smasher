import logging
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import List, Optional
from ftplib import FTP, all_errors
import numpy as np

from .config import ScannerConfig
from .utils.file_utils import read_ips


class FTPScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = self._setup_logging()

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

    def scan_server(self, ip: str) -> Optional[str]:
        """Attempt to connect and authenticate to an FTP server"""
        try:
            with FTP(ip, timeout=self.config.timeout) as ftp:
                ftp.login("anonymous", "anonymous@example.com")

                # Store directory listing in a list instead of printing
                dir_listing = []
                ftp.retrlines("LIST", dir_listing.append)

                self.logger.info(f"Successfully connected to {ip}")
                self.logger.debug(f"Directory listing for {
                                  ip}:\n" + "\n".join(dir_listing))

                return ip

        except all_errors as e:
            self.logger.debug(f"Failed to connect to {ip}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error scanning {ip}: {str(e)}")

        return None

    def process_ip_chunk(self, ip_list: List[str]) -> List[str]:
        """Process a chunk of IPs using a thread pool"""
        found_servers = []
        with ThreadPoolExecutor(max_workers=self.config.num_threads) as executor:
            results = executor.map(self.scan_server, ip_list)
            found_servers.extend([ip for ip in results if ip is not None])
        return found_servers

    def scan(self, ip_file: str) -> List[str]:
        """Main scanning method"""
        try:
            # Read and validate IP list
            ip_list = read_ips(ip_file)
            if not ip_list:
                self.logger.error("No valid IPs found in input file")
                return []

            # Split IPs among processes
            ip_chunks = np.array_split(ip_list, self.config.cpu_cores)

            # Use process pool for parallel processing
            with ProcessPoolExecutor(max_workers=self.config.cpu_cores) as executor:
                chunk_results = executor.map(self.process_ip_chunk, ip_chunks)

                # Combine results from all processes
                for servers in chunk_results:
                    self.config.servers_found.extend(servers)

            return self.config.servers_found

        except Exception as e:
            self.logger.error(f"Scanner error: {str(e)}")
            return []
