import random
from pathlib import Path
from typing import List


def read_ips(ip_file: str) -> List[str]:
    """Read and validate IP addresses from file"""
    ip_list = []
    ip_path = Path(ip_file)

    if not ip_path.exists():
        raise FileNotFoundError(f"IP file not found: {ip_file}")

    with ip_path.open() as f:
        ip_list = [line.strip() for line in f if line.strip()]

    random.shuffle(ip_list)
    return ip_list
