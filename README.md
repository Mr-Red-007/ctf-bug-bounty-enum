# ctf-bug-bounty-enum-

# CTF & Bug Bounty Enumeration Tool

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![PyQt6](https://img.shields.io/badge/PyQt6-6.6.1-orange.svg)

A comprehensive Linux GUI application for penetration testing, CTF competitions, and bug bounty hunting. Built with PyQt6 and Python 3.

## 🚀 Features

### Web Scanning Module
- **Subdomain Enumeration**: Multiple sources (crt.sh, DNSDumpster, DNS brute force)
- **Directory Busting**: OWASP common paths with status code detection
- **File Busting**: Multiple extension support (.php, .txt, .bak, etc.)
- **Technology Identification**: Frameworks, CMS, servers, CDN detection
- **Vulnerability Search**: ExploitDB, NIST CVE, GitHub POC integration
- **Smart Toggles**: Subdomain scan automatically applies to directory/file busting

### OS Enumeration Module
- **Port Scanning**: Common ports + full range option
- **Service Detection**: Banner grabbing and version identification
- **Vulnerability Mapping**: Known vulnerabilities per service
- **Security Recommendations**: Context-aware remediation suggestions
- **OWASP & NIST Compliance**: Built-in security framework checks

### Vulnerability Database
- **Multi-Source Search**: ExploitDB, NIST NVD, CVE.org integration
- **POC Availability**: Automatic GitHub POC finder
- **CVSS Scoring**: Vulnerability severity assessment
- **Export Capabilities**: JSON, CSV, PDF formats

### Advanced Features
- **Dynamic Checklist**: Suggestions adapt to toggle changes
- **Integrated Cheatsheets**: Penetration testing quick reference
- **Man Pages**: Built-in documentation
- **Dark Theme UI**: Optimized for extended use
- **Real-time Logging**: Live scan status updates
- **Async Operations**: Non-blocking scanning

## 📋 Requirements

### System Requirements
- Linux (Ubuntu 20.04+ recommended)
- Python 3.8+
- 4GB RAM minimum
- Internet connection for vulnerability database queries

### Optional Tools
- `nmap` - Advanced port scanning
- `gobuster` - Directory enumeration
- `whatweb` - Web technology identification
- `amass` - Advanced subdomain enumeration

## 🔧 Installation

### Quick Start

```bash
# Clone repository
git clone https://github.com/mr-redoo7i/ctf-bug-bounty-enum.git
cd ctf-bug-bounty-enum

# Install dependencies
pip install -r requirements.txt

# Run application
python main.py
