"""
Brute Force Attack Detection Engine
Detects authentication brute-force attempts and failed-to-success patterns
"""

import pandas as pd
from datetime import timedelta


class BruteForceDetector:
    def __init__(self, config):
        self.failed_threshold = config['detection']['brute_force']['failed_attempts_threshold']
        self.time_window = config['detection']['brute_force']['time_window_seconds']
        self.f2s_threshold = config['detection']['failed_to_success']['failed_attempts_before_success']
        self.f2s_window = config['detection']['failed_to_success']['time_window_seconds']
        
    def detect(self, auth_data):
        """Detect brute-force attacks in authentication data"""
        if auth_data.empty:
            return []
        
        alerts = []
        
        failed_auth = auth_data[auth_data['status'] == 'failure'].copy()
        
        if not failed_auth.empty:
            alerts.extend(self._detect_brute_force(failed_auth))
        
        alerts.extend(self._detect_failed_to_success(auth_data))
        
        return alerts
    
    def _detect_brute_force(self, failed_auth):
        """Detect brute-force based on failed attempt count"""
        alerts = []
        
        failed_auth = failed_auth.sort_values('timestamp')
        
        for ip in failed_auth['source_ip'].unique():
            if ip == 'localhost':
                continue
                
            ip_failures = failed_auth[failed_auth['source_ip'] == ip].copy()
            
            for i, row in ip_failures.iterrows():
                window_start = row['timestamp'] - timedelta(seconds=self.time_window)
                window_end = row['timestamp']
                
                attempts_in_window = ip_failures[
                    (ip_failures['timestamp'] >= window_start) &
                    (ip_failures['timestamp'] <= window_end)
                ]
                
                attempt_count = len(attempts_in_window)
                
                if attempt_count >= self.failed_threshold:
                    severity = self._calculate_severity(attempt_count)
                    
                    alerts.append({
                        'timestamp': row['timestamp'],
                        'source_ip': ip,
                        'service': row['service'],
                        'detection_type': 'brute_force',
                        'severity': severity,
                        'details': f"{attempt_count} failed authentication attempts within {self.time_window}s",
                        'attempt_count': attempt_count,
                        'confidence': min(0.9, 0.5 + (attempt_count / self.failed_threshold) * 0.4)
                    })
                    break
        
        return alerts
    
    def _detect_failed_to_success(self, auth_data):
        """Detect successful login after multiple failures (high-risk pattern)"""
        alerts = []
        
        auth_data = auth_data.sort_values('timestamp')
        
        for ip in auth_data['source_ip'].unique():
            if ip == 'localhost':
                continue
                
            ip_events = auth_data[auth_data['source_ip'] == ip].copy()
            
            successes = ip_events[ip_events['status'] == 'success']
            
            for _, success_row in successes.iterrows():
                window_start = success_row['timestamp'] - timedelta(seconds=self.f2s_window)
                
                prior_failures = ip_events[
                    (ip_events['timestamp'] >= window_start) &
                    (ip_events['timestamp'] < success_row['timestamp']) &
                    (ip_events['status'] == 'failure')
                ]
                
                failure_count = len(prior_failures)
                
                if failure_count >= self.f2s_threshold:
                    alerts.append({
                        'timestamp': success_row['timestamp'],
                        'source_ip': ip,
                        'service': success_row['service'],
                        'detection_type': 'failed_to_success',
                        'severity': 'high',
                        'details': f"Successful login after {failure_count} failed attempts (potential credential stuffing)",
                        'attempt_count': failure_count,
                        'confidence': 0.85
                    })
        
        return alerts
    
    def _calculate_severity(self, attempt_count):
        """Calculate severity based on attempt count"""
        if attempt_count >= 20:
            return 'critical'
        elif attempt_count >= 10:
            return 'high'
        elif attempt_count >= 7:
            return 'medium'
        else:
            return 'low'
