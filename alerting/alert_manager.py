"""
Alert Manager
Manages alert generation, formatting, and display
"""

from datetime import datetime


class AlertManager:
    def __init__(self, config):
        self.use_colors = config['output']['terminal_colors']
        
        self.colors = {
            'critical': '\033[91m',
            'high': '\033[93m',
            'medium': '\033[94m',
            'low': '\033[92m',
            'reset': '\033[0m',
            'bold': '\033[1m',
            'header': '\033[95m'
        }
        
    def display_alerts(self, alerts):
        """Display alerts in terminal with formatting"""
        if not alerts:
            print("\n[✓] No security alerts detected.")
            return
        
        print(f"\n{self._color('header', '='*80)}")
        print(f"{self._color('header', self._color('bold', 'SECURITY ALERTS DETECTED'))}")
        print(f"{self._color('header', '='*80)}\n")
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for alert in alerts:
            severity_counts[alert['severity']] += 1
            self._display_single_alert(alert)
        
        print(f"\n{self._color('header', '='*80)}")
        print(f"{self._color('bold', 'SUMMARY')}")
        print(f"{self._color('header', '='*80)}")
        print(f"Total Alerts: {len(alerts)}")
        print(f"  {self._color('critical', '●')} Critical: {severity_counts['critical']}")
        print(f"  {self._color('high', '●')} High: {severity_counts['high']}")
        print(f"  {self._color('medium', '●')} Medium: {severity_counts['medium']}")
        print(f"  {self._color('low', '●')} Low: {severity_counts['low']}")
        print(f"{self._color('header', '='*80)}\n")
    
    def _display_single_alert(self, alert):
        """Display a single alert with formatting"""
        severity = alert['severity'].upper()
        severity_colored = self._color(alert['severity'], f"[{severity}]")
        
        timestamp_str = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(alert['timestamp'], 'strftime') else str(alert['timestamp'])
        
        print(f"{severity_colored} {alert['detection_type'].replace('_', ' ').title()}")
        print(f"  Time: {timestamp_str}")
        print(f"  Source IP: {self._color('bold', alert['source_ip'])}")
        print(f"  Service: {alert['service']}")
        print(f"  Details: {alert['details']}")
        print(f"  Confidence: {alert['confidence']:.0%}")
        print()
    
    def _color(self, color_name, text):
        """Apply color to text if colors are enabled"""
        if not self.use_colors:
            return text
        
        color_code = self.colors.get(color_name, '')
        reset_code = self.colors['reset']
        
        return f"{color_code}{text}{reset_code}"
    
    def get_alert_summary(self, alerts):
        """Generate a text summary of alerts"""
        if not alerts:
            return "No security alerts detected."
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        ip_counts = {}
        service_counts = {}
        
        for alert in alerts:
            severity_counts[alert['severity']] += 1
            
            ip = alert['source_ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            service = alert['service']
            service_counts[service] = service_counts.get(service, 0) + 1
        
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        summary = []
        summary.append("="*80)
        summary.append("SOCWatch - Security Alert Summary")
        summary.append("="*80)
        summary.append(f"\nTotal Alerts: {len(alerts)}")
        summary.append(f"  Critical: {severity_counts['critical']}")
        summary.append(f"  High: {severity_counts['high']}")
        summary.append(f"  Medium: {severity_counts['medium']}")
        summary.append(f"  Low: {severity_counts['low']}")
        
        summary.append(f"\nTop Offending IPs:")
        for ip, count in top_ips:
            summary.append(f"  {ip}: {count} alerts")
        
        summary.append(f"\nMost Targeted Services:")
        for service, count in top_services:
            summary.append(f"  {service}: {count} alerts")
        
        summary.append("\n" + "="*80)
        
        return "\n".join(summary)
