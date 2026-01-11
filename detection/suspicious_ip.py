"""
Suspicious IP Behavior Detection
Detects scanning, abnormal request rates, and other suspicious patterns
"""

import pandas as pd
from datetime import timedelta


class SuspiciousIPDetector:
    def __init__(self, config):
        self.scan_threshold = config['detection']['scanning']['error_404_threshold']
        self.scan_window = config['detection']['scanning']['time_window_seconds']
        self.rate_threshold = config['detection']['request_rate']['request_threshold']
        self.rate_window = config['detection']['request_rate']['time_window_seconds']
        
    def detect(self, apache_data):
        """Detect suspicious IP behavior in web traffic"""
        if apache_data.empty:
            return []
        
        alerts = []
        
        alerts.extend(self._detect_scanning(apache_data))
        alerts.extend(self._detect_abnormal_rate(apache_data))
        alerts.extend(self._detect_suspicious_user_agents(apache_data))
        
        return alerts
    
    def _detect_scanning(self, apache_data):
        """Detect port/directory scanning via 404 errors"""
        alerts = []
        
        errors_404 = apache_data[apache_data['status_code'] == 404].copy()
        
        if errors_404.empty:
            return alerts
        
        errors_404 = errors_404.sort_values('timestamp')
        
        for ip in errors_404['source_ip'].unique():
            ip_errors = errors_404[errors_404['source_ip'] == ip].copy()
            
            for i, row in ip_errors.iterrows():
                window_start = row['timestamp'] - timedelta(seconds=self.scan_window)
                window_end = row['timestamp']
                
                errors_in_window = ip_errors[
                    (ip_errors['timestamp'] >= window_start) &
                    (ip_errors['timestamp'] <= window_end)
                ]
                
                error_count = len(errors_in_window)
                
                if error_count >= self.scan_threshold:
                    unique_uris = errors_in_window['uri'].nunique()
                    
                    severity = 'high' if error_count >= 20 else 'medium'
                    
                    alerts.append({
                        'timestamp': row['timestamp'],
                        'source_ip': ip,
                        'service': 'apache',
                        'detection_type': 'scanning',
                        'severity': severity,
                        'details': f"Scanning detected: {error_count} 404 errors ({unique_uris} unique URIs) in {self.scan_window}s",
                        'error_count': error_count,
                        'confidence': min(0.9, 0.6 + (error_count / self.scan_threshold) * 0.3)
                    })
                    break
        
        return alerts
    
    def _detect_abnormal_rate(self, apache_data):
        """Detect abnormally high request rates"""
        alerts = []
        
        apache_data = apache_data.sort_values('timestamp')
        
        for ip in apache_data['source_ip'].unique():
            ip_requests = apache_data[apache_data['source_ip'] == ip].copy()
            
            for i, row in ip_requests.iterrows():
                window_start = row['timestamp'] - timedelta(seconds=self.rate_window)
                window_end = row['timestamp']
                
                requests_in_window = ip_requests[
                    (ip_requests['timestamp'] >= window_start) &
                    (ip_requests['timestamp'] <= window_end)
                ]
                
                request_count = len(requests_in_window)
                
                if request_count >= self.rate_threshold:
                    severity = 'high' if request_count >= 100 else 'medium'
                    
                    alerts.append({
                        'timestamp': row['timestamp'],
                        'source_ip': ip,
                        'service': 'apache',
                        'detection_type': 'abnormal_request_rate',
                        'severity': severity,
                        'details': f"Abnormal request rate: {request_count} requests in {self.rate_window}s",
                        'request_count': request_count,
                        'confidence': 0.7
                    })
                    break
        
        return alerts
    
    def _detect_suspicious_user_agents(self, apache_data):
        """Detect suspicious or automated user agents"""
        alerts = []
        
        suspicious_patterns = [
            'nikto', 'nmap', 'masscan', 'sqlmap', 'metasploit',
            'burp', 'scanner', 'bot', 'crawler', 'spider'
        ]
        
        for pattern in suspicious_patterns:
            suspicious = apache_data[
                apache_data['user_agent'].str.lower().str.contains(pattern, na=False)
            ]
            
            for ip in suspicious['source_ip'].unique():
                ip_suspicious = suspicious[suspicious['source_ip'] == ip]
                
                if len(ip_suspicious) > 0:
                    first_occurrence = ip_suspicious.iloc[0]
                    
                    alerts.append({
                        'timestamp': first_occurrence['timestamp'],
                        'source_ip': ip,
                        'service': 'apache',
                        'detection_type': 'suspicious_user_agent',
                        'severity': 'medium',
                        'details': f"Suspicious user agent detected: '{first_occurrence['user_agent'][:50]}'",
                        'user_agent': first_occurrence['user_agent'],
                        'confidence': 0.75
                    })
                    break
        
        return alerts
