from dataclasses import dataclass
import os
import math
from typing import List

@dataclass
class ScannerConfig:
    """Configuration settings for the FTP scanner"""
    cpu_cores: int = math.floor(os.cpu_count() * 0.8)
    num_threads: int = 300
    timeout: int = 10
    servers_found: List[str] = None
    
    def __post_init__(self):
        self.servers_found = []