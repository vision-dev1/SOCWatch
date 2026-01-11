#!/usr/bin/env python3
"""
SOCWatch - SIEM Log Analyzer
A lightweight SOC-style security monitoring tool for detection engineering

Created by Vision (GitHub: https://github.com/vision-dev1)

ETHICAL USE DISCLAIMER:
This tool is designed exclusively for defensive security monitoring and educational purposes.
Use only on systems you own or have explicit authorization to monitor.
Unauthorized monitoring of systems is illegal and unethical.
"""

import argparse
import yaml
import sys
import os
from datetime import datetime

from parsers import AuthLogParser, SSHLogParser, ApacheLogParser
from detection import BruteForceDetector, SuspiciousIPDetector, PatternDetector
from correlation import AlertCorrelator
from alerting import AlertManager, ReportGenerator
from utils import deduplicate_alerts


ASCII_BANNER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███████╗ ██████╗  ██████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗  ║
║   ██╔════╝██╔═══██╗██╔════╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║  ║
║   ███████╗██║   ██║██║     ██║ █╗ ██║███████║   ██║   ██║     ███████║  ║
║   ╚════██║██║   ██║██║     ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║  ║
║   ███████║╚██████╔╝╚██████╗╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║  ║
║   ╚══════╝ ╚═════╝  ╚═════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝  ║
║                                                                           ║
║                    SIEM Log Analyzer & Threat Detector                   ║
║                  Security Operations Center Monitoring Tool              ║
║                                                                           ║
║                Created by Vision (github.com/vision-dev1)                ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""


def load_config(config_path):
    """Load YAML configuration file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[!] Configuration file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"[!] Error parsing configuration file: {e}")
        sys.exit(1)


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='SOCWatch - SIEM Log Analyzer for Security Monitoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python socwatch.py --config config/config.yaml
  python socwatch.py --auth /var/log/auth.log --ssh /var/log/ssh.log
  python socwatch.py --config config/config.yaml --no-color
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config/config.yaml',
        help='Path to configuration file (default: config/config.yaml)'
    )
    
    parser.add_argument(
        '--auth',
        help='Path to Linux auth log file (overrides config)'
    )
    
    parser.add_argument(
        '--ssh',
        help='Path to SSH log file (overrides config)'
    )
    
    parser.add_argument(
        '--apache',
        help='Path to Apache access log file (overrides config)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output directory for reports (overrides config)'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored terminal output'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress banner and progress messages'
    )
    
    return parser.parse_args()


def main():
    """Main SOCWatch execution flow"""
    args = parse_arguments()
    
    if not args.quiet:
        print(ASCII_BANNER)
        print("[*] SOCWatch SIEM Log Analyzer Starting...")
        print("[*] Defensive Security Monitoring Tool")
        print()
    
    config = load_config(args.config)
    
    if args.no_color:
        config['output']['terminal_colors'] = False
    
    if args.output:
        config['output']['output_directory'] = args.output
    
    auth_log = args.auth or config['log_sources']['auth_log']
    ssh_log = args.ssh or config['log_sources']['ssh_log']
    apache_log = args.apache or config['log_sources']['apache_log']
    
    if not args.quiet:
        print("[*] Loading log parsers...")
    
    auth_parser = AuthLogParser()
    ssh_parser = SSHLogParser()
    apache_parser = ApacheLogParser()
    
    if not args.quiet:
        print("[*] Parsing log files...")
    
    auth_data = auth_parser.parse(auth_log)
    ssh_data = ssh_parser.parse(ssh_log)
    apache_data = apache_parser.parse(apache_log)
    
    if not args.quiet:
        print(f"    - Auth log entries: {len(auth_data)}")
        print(f"    - SSH log entries: {len(ssh_data)}")
        print(f"    - Apache log entries: {len(apache_data)}")
        print()
    
    if not args.quiet:
        print("[*] Running detection engines...")
    
    bf_detector = BruteForceDetector(config)
    ip_detector = SuspiciousIPDetector(config)
    pattern_detector = PatternDetector(config)
    
    all_alerts = []
    
    import pandas as pd
    combined_auth = pd.concat([auth_data, ssh_data], ignore_index=True) if not auth_data.empty or not ssh_data.empty else pd.DataFrame()
    
    if not combined_auth.empty:
        all_alerts.extend(bf_detector.detect(combined_auth))
    
    if not apache_data.empty:
        all_alerts.extend(ip_detector.detect(apache_data))
    
    all_data = {
        'auth': combined_auth,
        'apache': apache_data
    }
    all_alerts.extend(pattern_detector.detect(all_data))
    
    if not args.quiet:
        print(f"    - Initial detections: {len(all_alerts)}")
        print()
    
    if not args.quiet:
        print("[*] Performing cross-source correlation...")
    
    correlator = AlertCorrelator(config)
    correlated_alerts = correlator.correlate(all_alerts)
    
    final_alerts = deduplicate_alerts(correlated_alerts)
    
    if not args.quiet:
        print(f"    - Final alerts after correlation: {len(final_alerts)}")
        print()
    
    alert_manager = AlertManager(config)
    alert_manager.display_alerts(final_alerts)
    
    if not args.quiet:
        print("[*] Generating reports...")
    
    report_gen = ReportGenerator(config)
    report_files = report_gen.generate_reports(final_alerts, alert_manager)
    
    if not args.quiet:
        print()
        print("[✓] SOCWatch analysis complete!")
        print()
        print("="*80)
        print("ETHICAL USE REMINDER:")
        print("This tool is for defensive security monitoring and education only.")
        print("Always obtain proper authorization before monitoring any systems.")
        print("="*80)
        print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
