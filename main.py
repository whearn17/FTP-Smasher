from src.config import ScannerConfig
from src.scanner import FTPScanner
import argparse
import math
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="FTP Server Scanner")
    parser.add_argument("-i", "--input-file", type=str, required=True,
                        help="File containing list of IPs to scan")
    parser.add_argument("-t", "--threads", type=int, default=300,
                        help="Number of threads per process")
    parser.add_argument("-c", "--cpu-cores", type=int,
                        default=math.floor(os.cpu_count() * 0.8),
                        help="Number of CPU cores to use")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Connection timeout in seconds")

    args = parser.parse_args()

    # Initialize configuration
    config = ScannerConfig(
        cpu_cores=args.cpu_cores,
        num_threads=args.threads,
        timeout=args.timeout
    )

    # Create and run scanner
    scanner = FTPScanner(config)
    found_servers = scanner.scan(args.input_file)

    # Output results
    print(f"\nScan Complete - Found {len(found_servers)} servers")
    if found_servers:
        print("\nFound Servers:")
        print("\n".join(found_servers))


if __name__ == "__main__":
    main()