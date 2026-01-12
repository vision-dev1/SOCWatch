# SOCWatch - SIEM Log Analyzer

![SOCWatch Badge](https://img.shields.io/badge/Security-SOCWatch-red)
![Python Badge](https://img.shields.io/badge/Made%20with-Python-blue)
![License Badge](https://img.shields.io/badge/license-MIT-blue.svg)

**A lightweight, SOC-style SIEM Log Analyzer designed for detection engineering and security monitoring.**

SOCWatch simulates how a real Security Operations Center (SOC) analyzes logs by ingesting, parsing, correlating, and generating alerts from multiple log sources. It is built to demonstrate detection engineering concepts, log analysis techniques, and threat correlation.

---

## 🛡️ Features

- **Multi-Source Log Ingestion**: Parses Linux auth logs, SSH service logs, and Apache access logs.
- **Advanced Threat Detection**:
  - **Brute-Force Attacks**: Identifies repeated authentication failures.
  - **Suspicious IP Behavior**: Detects port/directory scanning (404s) and abnormal request rates.
  - **Attack Patterns**: Flags failed-to-success login patterns (potential credential stuffing) and privilege escalation attempts.
- **Cross-Source Correlation**: Correlates suspicious activity across multiple log sources to identify coordinated attacks with higher confidence.
- **Smart Alerting**: Assigns severity levels (Low, Medium, High, Critical) and confidence scores to alerts.
- **Reporting**: Generates professional JSON exports for SIEM integration and human-readable summary reports for SOC analysts.

---

## 🚀 Installation & Usage

### Prerequisites

- Python 3.8+
- Dependencies listed in `requirements.txt`

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/vision-dev1/SOCWatch.git
   cd SOCWatch
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Tool

**Basic usage with default configuration:**
```bash
python socwatch.py
```

**Analyze specific log files:**
```bash
python socwatch.py --auth /var/log/auth.log --ssh /var/log/ssh.log --apache /var/log/apache2/access.log
```

**Use a custom configuration:**
```bash
python socwatch.py --config config/custom_config.yaml
```

**Export reports to a specific directory:**
```bash
python socwatch.py --output ./reports
```

---

## 🧠 Detection Logic

SOCWatch uses a modular detection engine to identify security threats:

1. **Brute-Force Detection**:
   - Tracks failed authentication attempts per IP within a configurable time window (default: 5 failures in 5 mins).
   - **Severity**: Scales from Low to Critical based on attempt volume.

2. **Scanning & Reconnaissance**:
   - Analyzes web logs for high volumes of 404 errors (directory bruteforcing or vulnerability scanning).
   - **Signature Detection**: Identifies known malicious user agents (e.g., Nikto, Nmap, SQLMap).

3. **Behavioral Anomalies**:
   - **Failed-to-Success Pattern**: Flags when an IP fails multiple times and then succeeds (highly indicative of a successful brute-force or credential stuffing).
   - **Abnormal Request Rate**: Detects DOS-like behavior or aggressive scraping (default: 50+ requests/min).
   - **Privilege Escalation**: Monitors for repeated `sudo` failures.

4. **Correlation Engine**:
   - Aggregates unique alerts by Source IP.
   - Elevates severity if an IP is attacking multiple services (e.g., SSH brute-force + Web scanning).
   - Increases confidence score for cross-correlated events.

---

## 📊 Sample Output

**Terminal Output:**
```text
[HIGH] Brute Force Detected
  Time: 2026-01-11 14:23:45
  Source IP: 192.168.1.100
  Service: ssh
  Details: 15 failed authentication attempts within 300s
  Confidence: 90%

[CRITICAL] Cross-Source Correlation
  Time: 2026-01-11 14:25:10
  Source IP: 10.0.0.50
  Service: multiple (ssh, apache)
  Details: Coordinated attack detected across 2 services: brute_force, scanning
  Confidence: 95%
```

**Summary Report:**
Generated in `output/summary_TIMESTAMP.txt`, providing a high-level overview for SOC management.

---

## ⚠️ Ethical Use Disclaimer

**This tool is designed exclusively for defensive security monitoring and educational purposes.**

- **Do not** use this tool to monitor systems you do not own or have explicit permission to audit.
- **Do not** use the detection logic or code to build offensive tools.
- The author is not responsible for any misuse of this software.

---

## 👤 Author

**Created by Vision**
- [Github](https://github.com/vision-dev1)
- [Portfolio](https://visionkc.com.np)

