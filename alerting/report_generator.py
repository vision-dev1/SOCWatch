"""
Report Generator
Generates JSON and summary reports for SOC review
"""

import json
from datetime import datetime
import os


class ReportGenerator:
    def __init__(self, config):
        self.output_dir = config['output']['output_directory']
        self.json_enabled = config['output']['json_export']
        self.summary_enabled = config['output']['summary_report']
        
    def generate_reports(self, alerts, alert_manager):
        """Generate all configured reports"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        report_files = []
        
        if self.json_enabled:
            json_file = self._generate_json_report(alerts, timestamp)
            if json_file:
                report_files.append(json_file)
        
        if self.summary_enabled:
            summary_file = self._generate_summary_report(alerts, alert_manager, timestamp)
            if summary_file:
                report_files.append(summary_file)
        
        return report_files
    
    def _generate_json_report(self, alerts, timestamp):
        """Generate JSON report with all alert details"""
        json_path = os.path.join(self.output_dir, f'alerts_{timestamp}.json')
        
        serializable_alerts = []
        for alert in alerts:
            alert_copy = alert.copy()
            
            if hasattr(alert_copy['timestamp'], 'isoformat'):
                alert_copy['timestamp'] = alert_copy['timestamp'].isoformat()
            else:
                alert_copy['timestamp'] = str(alert_copy['timestamp'])
            
            serializable_alerts.append(alert_copy)
        
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'total_alerts': len(alerts),
            'alerts': serializable_alerts
        }
        
        try:
            with open(json_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            print(f"[+] JSON report saved: {json_path}")
            return json_path
        except Exception as e:
            print(f"[!] Error generating JSON report: {e}")
            return None
    
    def _generate_summary_report(self, alerts, alert_manager, timestamp):
        """Generate human-readable summary report"""
        summary_path = os.path.join(self.output_dir, f'summary_{timestamp}.txt')
        
        try:
            summary_text = alert_manager.get_alert_summary(alerts)
            
            full_report = []
            full_report.append("SOCWatch - Security Operations Center Alert Report")
            full_report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            full_report.append("")
            full_report.append(summary_text)
            full_report.append("\n\nDETAILED ALERTS:")
            full_report.append("="*80)
            
            for i, alert in enumerate(alerts, 1):
                timestamp_str = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(alert['timestamp'], 'strftime') else str(alert['timestamp'])
                
                full_report.append(f"\nAlert #{i} - [{alert['severity'].upper()}]")
                full_report.append(f"  Type: {alert['detection_type'].replace('_', ' ').title()}")
                full_report.append(f"  Time: {timestamp_str}")
                full_report.append(f"  Source IP: {alert['source_ip']}")
                full_report.append(f"  Service: {alert['service']}")
                full_report.append(f"  Details: {alert['details']}")
                full_report.append(f"  Confidence: {alert['confidence']:.0%}")
            
            full_report.append("\n" + "="*80)
            full_report.append("\nRECOMMENDED ACTIONS:")
            full_report.append("  1. Review and investigate all CRITICAL and HIGH severity alerts")
            full_report.append("  2. Block or rate-limit IPs with multiple alerts")
            full_report.append("  3. Check for successful logins from flagged IPs")
            full_report.append("  4. Review firewall and IDS/IPS rules")
            full_report.append("  5. Consider implementing additional authentication controls")
            full_report.append("\n" + "="*80)
            full_report.append("\nCreated by Vision (GitHub: https://github.com/vision-dev1)")
            full_report.append("SOCWatch - Defensive Security Monitoring Tool")
            full_report.append("="*80)
            
            with open(summary_path, 'w') as f:
                f.write('\n'.join(full_report))
            
            print(f"[+] Summary report saved: {summary_path}")
            return summary_path
        except Exception as e:
            print(f"[!] Error generating summary report: {e}")
            return None
