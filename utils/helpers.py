"""
Utility Helper Functions
Common utilities for SOCWatch
"""

import re
from datetime import datetime


def is_valid_ip(ip_address):
    """Validate IPv4 address format"""
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not pattern.match(ip_address):
        return False
    
    octets = ip_address.split('.')
    for octet in octets:
        if int(octet) > 255:
            return False
    
    return True


def normalize_timestamp(timestamp_str, format_str='%b %d %H:%M:%S'):
    """Normalize timestamp string to datetime object"""
    try:
        dt = datetime.strptime(timestamp_str, format_str)
        dt = dt.replace(year=datetime.now().year)
        return dt
    except Exception:
        return None


def format_timestamp(dt):
    """Format datetime object to readable string"""
    if hasattr(dt, 'strftime'):
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return str(dt)


def deduplicate_alerts(alerts):
    """Remove duplicate alerts based on key attributes"""
    seen = set()
    unique_alerts = []
    
    for alert in alerts:
        key = (
            alert['source_ip'],
            alert['detection_type'],
            alert['service']
        )
        
        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)
    
    return unique_alerts


def get_severity_color(severity):
    """Get ANSI color code for severity level"""
    colors = {
        'critical': '\033[91m',
        'high': '\033[93m',
        'medium': '\033[94m',
        'low': '\033[92m'
    }
    return colors.get(severity, '\033[0m')
