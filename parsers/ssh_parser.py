"""
SSH Service Log Parser
Parses SSH-specific connection and authentication logs
"""

import re
import pandas as pd
from datetime import datetime


class SSHLogParser:
    def __init__(self):
        self.patterns = {
            'connection_attempt': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Connection from (\d+\.\d+\.\d+\.\d+)'
            ),
            'failed_auth': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
            ),
            'accepted_auth': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)'
            ),
            'disconnected': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Disconnected from (?:invalid user )?(?:\S+ )?(\d+\.\d+\.\d+\.\d+)'
            ),
            'invalid_user': re.compile(
                r'(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
            )
        }
        
    def parse(self, log_file_path):
        """Parse SSH log file and return structured DataFrame"""
        entries = []
        
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self._parse_line(line)
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            print(f"[!] SSH log file not found: {log_file_path}")
            return pd.DataFrame()
        
        if not entries:
            return pd.DataFrame()
            
        df = pd.DataFrame(entries)
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce')
        df['timestamp'] = df['timestamp'].apply(lambda x: x.replace(year=datetime.now().year) if pd.notna(x) else x)
        
        return df
    
    def _parse_line(self, line):
        """Parse a single SSH log line"""
        if 'invalid_user' in line.lower():
            match = self.patterns['invalid_user'].search(line)
            if match:
                return {
                    'timestamp': match.group(1),
                    'event_type': 'invalid_user',
                    'service': 'ssh',
                    'username': match.group(2),
                    'source_ip': match.group(3),
                    'status': 'failure'
                }
        
        if 'failed' in line.lower():
            match = self.patterns['failed_auth'].search(line)
            if match:
                return {
                    'timestamp': match.group(1),
                    'event_type': 'ssh_failed',
                    'service': 'ssh',
                    'username': match.group(2),
                    'source_ip': match.group(3),
                    'status': 'failure'
                }
        
        if 'accepted' in line.lower():
            match = self.patterns['accepted_auth'].search(line)
            if match:
                return {
                    'timestamp': match.group(1),
                    'event_type': 'ssh_success',
                    'service': 'ssh',
                    'username': match.group(2),
                    'source_ip': match.group(3),
                    'status': 'success'
                }
        
        if 'connection from' in line.lower():
            match = self.patterns['connection_attempt'].search(line)
            if match:
                return {
                    'timestamp': match.group(1),
                    'event_type': 'connection',
                    'service': 'ssh',
                    'username': 'unknown',
                    'source_ip': match.group(2),
                    'status': 'info'
                }
        
        return None
