"""
Threat detection patterns and signatures
"""
import re

# Suspicious patterns with severity levels
THREAT_PATTERNS = {
    "SQL Injection Attempt": {
        "pattern": re.compile(
            r"(union\s+select|drop\s+table|insert\s+into|"
            r"1=1|or\s+'1'='1|xp_cmdshell|exec\s*\()",
            re.IGNORECASE
        ),
        "severity": "Critical"
    },
    "XSS Attempt": {
        "pattern": re.compile(
            r"(<script|javascript:|onerror=|onload=|alert\(|"
            r"document\.cookie|eval\()",
            re.IGNORECASE
        ),
        "severity": "High"
    },
    "Path Traversal": {
        "pattern": re.compile(
            r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e|/etc/passwd|/etc/shadow)",
            re.IGNORECASE
        ),
        "severity": "High"
    },
    "Command Injection": {
        "pattern": re.compile(
            r"(;\s*ls|;\s*cat|;\s*whoami|;\s*id\s|"
            r"\|\s*nc\s|\|\s*bash|`.*`|\$\(.*\))",
            re.IGNORECASE
        ),
        "severity": "Critical"
    },
    "Scanner/Bot Detected": {
        "pattern": re.compile(
            r"(nikto|sqlmap|nmap|masscan|zgrab|"
            r"dirbuster|gobuster|wfuzz|hydra)",
            re.IGNORECASE
        ),
        "severity": "Medium"
    },
    "Brute Force Indicator": {
        "pattern": re.compile(
            r"(Failed password|authentication failure|"
            r"Invalid user|login failed)",
            re.IGNORECASE
        ),
        "severity": "High"
    },
    "Sensitive File Access": {
        "pattern": re.compile(
            r"(\.env|wp-config\.php|config\.php|"
            r"\.git/config|\.htpasswd|id_rsa|shadow|passwd)",
            re.IGNORECASE
        ),
        "severity": "High"
    },
    "Admin Panel Access": {
        "pattern": re.compile(
            r"(/admin|/wp-admin|/phpmyadmin|"
            r"/manager/html|/console|/dashboard)",
            re.IGNORECASE
        ),
        "severity": "Medium"
    },
}

# Apache/Nginx combined log format parser
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+-\s+-\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)'
)

# Auth log parser (Linux /var/log/auth.log)
AUTH_LOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+'
    r'(?P<host>\S+)\s+(?P<service>[^:]+):\s+(?P<message>.+)'
)