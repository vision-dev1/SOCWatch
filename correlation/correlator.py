"""
Cross-Source Correlation Engine
Correlates alerts across multiple log sources to identify coordinated attacks
"""

from collections import defaultdict


class AlertCorrelator:
    def __init__(self, config):
        self.cross_source_multiplier = config['correlation']['cross_source_multiplier']
        self.min_confidence = config['correlation']['min_confidence_score']
        
    def correlate(self, all_alerts):
        """Correlate alerts across log sources by IP address"""
        if not all_alerts:
            return []
        
        ip_alerts = defaultdict(list)
        
        for alert in all_alerts:
            ip_alerts[alert['source_ip']].append(alert)
        
        correlated_alerts = []
        
        for ip, alerts in ip_alerts.items():
            if len(alerts) > 1:
                services = set(alert['service'] for alert in alerts)
                
                if len(services) > 1:
                    correlated_alert = self._create_correlated_alert(ip, alerts, services)
                    correlated_alerts.append(correlated_alert)
            
            for alert in alerts:
                if alert['confidence'] >= self.min_confidence:
                    correlated_alerts.append(alert)
        
        correlated_alerts = sorted(
            correlated_alerts,
            key=lambda x: (self._severity_rank(x['severity']), x['confidence']),
            reverse=True
        )
        
        return correlated_alerts
    
    def _create_correlated_alert(self, ip, alerts, services):
        """Create a high-confidence correlated alert"""
        latest_alert = max(alerts, key=lambda x: x['timestamp'])
        
        detection_types = [alert['detection_type'] for alert in alerts]
        max_severity = self._get_max_severity([alert['severity'] for alert in alerts])
        
        avg_confidence = sum(alert['confidence'] for alert in alerts) / len(alerts)
        boosted_confidence = min(0.95, avg_confidence * self.cross_source_multiplier)
        
        elevated_severity = self._elevate_severity(max_severity)
        
        return {
            'timestamp': latest_alert['timestamp'],
            'source_ip': ip,
            'service': f"multiple ({', '.join(services)})",
            'detection_type': 'cross_source_correlation',
            'severity': elevated_severity,
            'details': f"Coordinated attack detected across {len(services)} services: {', '.join(detection_types)}",
            'confidence': boosted_confidence,
            'correlated_alerts': len(alerts),
            'affected_services': list(services)
        }
    
    def _get_max_severity(self, severities):
        """Get the highest severity from a list"""
        severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        max_sev = max(severities, key=lambda x: severity_order.get(x, 0))
        return max_sev
    
    def _elevate_severity(self, current_severity):
        """Elevate severity for correlated alerts"""
        elevation_map = {
            'low': 'medium',
            'medium': 'high',
            'high': 'critical',
            'critical': 'critical'
        }
        return elevation_map.get(current_severity, current_severity)
    
    def _severity_rank(self, severity):
        """Convert severity to numeric rank for sorting"""
        ranks = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return ranks.get(severity, 0)
