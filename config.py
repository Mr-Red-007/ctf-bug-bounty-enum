"""
Configuration file for CTF & Bug Bounty Enumeration Tool
"""
import os
from pathlib import Path

# API Keys
GOOGLE_API_KEY = "*************************"
GOOGLE_SEARCH_ENGINE_ID = "YOUR_SEARCH_ENGINE_ID"  # Create at https://cse.google.com/cse/

# Application Settings
APP_VERSION = "1.0.0"
APP_NAME = "CTF & Bug Bounty Enum Tool"
DEBUG = True

# Paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

# Create directories if they don't exist
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# Web Scanning Config
WEB_CONFIG = {
    "timeout": 10,
    "retries": 3,
    "threads": 5,
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
}

# OS Enumeration Config
OS_CONFIG = {
    "timeout": 30,
    "port_range": "1-65535",
    "common_ports": [22, 80, 443, 3306, 5432, 8080, 8443, 9200, 27017]
}

# Vulnerability Sources
VULN_SOURCES = {
    "cve": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
    "exploitdb": "https://www.exploit-db.com/",
    "nist": "https://nvd.nist.gov/vuln/detail/",
    "shodan": "https://www.shodan.io/",
}

# OWASP & NIST Checklist
OWASP_CATEGORIES = {
    "A01_Broken_Access_Control",
    "A02_Cryptographic_Failures",
    "A03_Injection",
    "A04_Insecure_Design",
    "A05_Security_Misconfiguration",
    "A06_Vulnerable_Components",
    "A07_Authentication_Failures",
    "A08_Data_Integrity_Failures",
    "A09_Logging_Monitoring",
    "A10_SSRF"
}
