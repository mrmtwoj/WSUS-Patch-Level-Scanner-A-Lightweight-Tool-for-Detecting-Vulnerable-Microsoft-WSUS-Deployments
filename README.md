# WSUS-Patch-Level-Scanner-A-Lightweight-Tool-for-Detecting-Vulnerable-Microsoft-WSUS-Deployments

## Introduction

In this article, we introduce a lightweight multi-threaded WSUS Patch-Level Scanner designed to help administrators quickly identify outdated or vulnerable WSUS servers. The tool supports SOAP-based fingerprinting, version extraction, KB mapping, and flexible input handling such as single IP, lists, and CIDR ranges.

## Why WSUS Patch-Level Scanning Matters

+ Many organizations still rely on WSUS for centralized Windows updates.
+ Misconfigured or outdated WSUS servers expose organizations to man-in-the-middle attacks, spoofed updates, or patch manipulation.
+ Automated scanning helps identify weak points before attackers exploit them.

## Key Features
+ Multi-threaded scanning (fast)
+ Detection of unpatched / outdated WSUS versions
+ SOAP fingerprinting on ports 8530 (HTTP) and 8531 (SSL)

## Support for:
+ -t < target or list >
+ File-based input (@targets.txt)
+ CIDR range parsing
+ Output formats: JSON, CSV, HTML
+ Proxy support
+ Retry/timeout control
+ Lightweight Python code, easily extensible
+ Banner, help, and full command-line interface

## How the Scanner Works
+ The scanner checks:
+ WSUS port availability
+ SOAP/WSDL server responses
+ ServerVersion / BuildNumber pattern
+ Patch KB comparison against a small built-in vulnerability database

If the version matches a known vulnerable build, it marks the target as Vulnerable.
Otherwise, it categorizes the server as Potentially Patched or Unknown.

# Installation
```bash
https://github.com/mrmtwoj/WSUS-Patch-Level-Scanner-A-Lightweight-Tool-for-Detecting-Vulnerable-Microsoft-WSUS-Deployments.git
```

## Usage Examples
```bash
python wsus_scanner_enhanced.py -t 192.168.1.20
```
## Scan multiple IPs
```bash
python wsus_scanner_enhanced.py -t 192.168.1.20,192.168.1.21
```
## Scan from file
```bash
python wsus_scanner_enhanced.py -t @targets.txt
```
## Scan a CIDR
```bash
python wsus_scanner_enhanced.py -t 10.0.0.0/24 -c 50
```
## Export report
```bash
python wsus_scanner_enhanced.py -t @targets.txt -o report.html -f html
```

# Example Output
``` bash
{
  "target": "192.168.1.20",
  "status": "vulnerable",
  "build": "10.0.14393.0",
  "port": 8530,
  "notes": "Matches vulnerable WSUS build pattern CVE list"
}
```

# Future Improvements
+ Full CVE database mapping
+ Deep WSDL/metadata parsing
+ TLS certificate fingerprinting
+ Integration with vulnerability dashboards (ELK, Splunk, OpenVAS)

# Conclusion
This WSUS Patch-Level Scanner provides system administrators and security teams with a powerful yet lightweight tool for identifying unpatched or vulnerable WSUS servers across their networks. The script is intentionally modular and easy to extend, making it suitable for both enterprise auditing and research applications.

# Output Example

``` bash
{
  "target": "192.168.1.20",
  "status": "vulnerable",
  "build": "10.0.14393.0"
}
```
