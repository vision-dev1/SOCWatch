"""
Linux Authentication Log Parser
Parses /var/log/auth.log for authentication events
"""

import re
import pandas as pd
from datetime import datetime


class AuthLogParser:
    def __init__(self):
        self.patterns = {
            'failed_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
            ),
            'accepted_password': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)'
            ),
            'failed_sudo': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo:.*authentication failure.*user=(\S+)'
            ),
            'accepted_sudo': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo:.*(\S+) : TTY=.*COMMAND='
            )
        }
        
    def parse(self, log_file_path):
        """Parse authentication log file and return structured DataFrame"""
        entries = []
        
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self._parse_line(line)
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            print(f"[!] Auth log file not found: {log_file_path}")
            return pd.DataFrame()
        
        if not entries:
            return pd.DataFrame()
            
        df = pd.DataFrame(entries)
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce')
        df['timestamp'] = df['timestamp'].apply(lambda x: x.replace(year=datetime.now().year) if pd.notna(x) else x)
        
        return df
    
    def _parse_line(self, line):
        """Parse a single log line"""
        for event_type, pattern in self.patterns.items():
            match = pattern.search(line)
            if match:
                if 'failed_password' in event_type:
                    return {
                        'timestamp': match.group(1),
                        'event_type': 'auth_failed',
                        'service': 'ssh',
                        'username': match.group(2),
                        'source_ip': match.group(3),
                        'status': 'failure'
                    }
                elif 'accepted_password' in event_type:
                    return {
                        'timestamp': match.group(1),
                        'event_type': 'auth_success',
                        'service': 'ssh',
                        'username': match.group(2),
                        'source_ip': match.group(3),
                        'status': 'success'
                    }
                elif 'failed_sudo' in event_type:
                    return {
                        'timestamp': match.group(1),
                        'event_type': 'sudo_failed',
                        'service': 'sudo',
                        'username': match.group(2),
                        'source_ip': 'localhost',
                        'status': 'failure'
                    }
                elif 'accepted_sudo' in event_type:
                    return {
                        'timestamp': match.group(1),
                        'event_type': 'sudo_success',
                        'service': 'sudo',
                        'username': match.group(2),
                        'source_ip': 'localhost',
                        'status': 'success'
                    }
        return None
