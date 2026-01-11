"""
Advanced Attack Pattern Detection
Detects multi-stage attacks and complex behavioral patterns
"""

import pandas as pd
from datetime import timedelta


class PatternDetector:
    def __init__(self, config):
        self.config = config
        
    def detect(self, all_data):
        """Detect advanced attack patterns across all log sources"""
        alerts = []
        
        alerts.extend(self._detect_privilege_escalation(all_data))
        alerts.extend(self._detect_time_based_patterns(all_data))
        
        return alerts
    
    def _detect_privilege_escalation(self, all_data):
        """Detect potential privilege escalation attempts"""
        alerts = []
        
        auth_data = all_data.get('auth', pd.DataFrame())
        
        if auth_data.empty:
            return alerts
        
        sudo_attempts = auth_data[auth_data['service'] == 'sudo']
        
        for ip in sudo_attempts['source_ip'].unique():
            if ip == 'localhost':
                continue
                
            ip_sudo = sudo_attempts[sudo_attempts['source_ip'] == ip]
            failed_sudo = ip_sudo[ip_sudo['status'] == 'failure']
            
            if len(failed_sudo) >= 3:
                alerts.append({
                    'timestamp': failed_sudo.iloc[-1]['timestamp'],
                    'source_ip': ip,
                    'service': 'sudo',
                    'detection_type': 'privilege_escalation_attempt',
                    'severity': 'high',
                    'details': f"Multiple sudo failures detected ({len(failed_sudo)} attempts)",
                    'confidence': 0.8
                })
        
        return alerts
    
    def _detect_time_based_patterns(self, all_data):
        """Detect suspicious time-based patterns (e.g., off-hours access)"""
        alerts = []
        
        auth_data = all_data.get('auth', pd.DataFrame())
        
        if auth_data.empty:
            return alerts
        
        successes = auth_data[auth_data['status'] == 'success']
        
        for _, row in successes.iterrows():
            if pd.notna(row['timestamp']):
                hour = row['timestamp'].hour
                
                if hour >= 0 and hour <= 5:
                    alerts.append({
                        'timestamp': row['timestamp'],
                        'source_ip': row['source_ip'],
                        'service': row['service'],
                        'detection_type': 'off_hours_access',
                        'severity': 'low',
                        'details': f"Successful authentication during off-hours ({hour:02d}:00)",
                        'confidence': 0.5
                    })
        
        return alerts
