"""
Apache Access Log Parser
Parses Apache/NGINX access logs for web traffic analysis
"""

import re
import pandas as pd
from datetime import datetime


class ApacheLogParser:
    def __init__(self):
        self.pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) (.*?) HTTP/.*?" (\d+) (\d+|-) "(.*?)" "(.*?)"'
        )
        
    def parse(self, log_file_path):
        """Parse Apache access log file and return structured DataFrame"""
        entries = []
        
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self._parse_line(line)
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            print(f"[!] Apache log file not found: {log_file_path}")
            return pd.DataFrame()
        
        if not entries:
            return pd.DataFrame()
            
        df = pd.DataFrame(entries)
        # Parse timestamp with timezone then convert to naive (remove timezone)
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
        df['timestamp'] = df['timestamp'].dt.tz_localize(None)
        
        return df
    
    def _parse_line(self, line):
        """Parse a single Apache access log line"""
        match = self.pattern.search(line)
        if match:
            source_ip = match.group(1)
            timestamp = match.group(2)
            method = match.group(3)
            uri = match.group(4)
            status_code = int(match.group(5))
            response_size = match.group(6)
            referer = match.group(7)
            user_agent = match.group(8)
            
            response_size = int(response_size) if response_size != '-' else 0
            
            return {
                'timestamp': timestamp,
                'source_ip': source_ip,
                'method': method,
                'uri': uri,
                'status_code': status_code,
                'response_size': response_size,
                'referer': referer,
                'user_agent': user_agent,
                'service': 'apache'
            }
        
        return None
