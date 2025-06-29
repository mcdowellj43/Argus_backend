import sys
import os
from pathlib import Path

# Configuration
PORT = 8000
HOST = "localhost"

# Add the Argus root directory to Python path
current_dir = Path.cwd()
argus_root = current_dir.parent.parent  # Go up from web/backend to argus root
sys.path.insert(0, str(argus_root))

print(f"📁 Current directory: {current_dir}")
print(f"📁 Argus root directory: {argus_root}")

# Module-specific timeout configuration (in seconds)
MODULE_TIMEOUTS = {
    'data_leak.py': 1200,              # 20 minutes - API rate limited
    'subdomain_enum.py': 180,         # 3 minutes - DNS enumeration
    'subdomain_takeover.py': 240,     # 4 minutes - comprehensive testing
    'virustotal_scan.py': 120,        # 2 minutes - API dependent
    'email_harvester.py': 300,        # 5 minutes - comprehensive search
    'shodan.py': 180,                 # 3 minutes - API dependent
    'pastebin_monitoring.py': 180,    # 3 minutes - API dependent
    'exposed_env_files.py': 120,      # 2 minutes - file checking
    'default': 60                     # 1 minute for all other modules
}

def get_module_timeout(module_script):
    """Get timeout for specific module, fallback to default"""
    return MODULE_TIMEOUTS.get(module_script, MODULE_TIMEOUTS['default'])

# Enhanced modules list - All modules with centralized binary findings system
ENHANCED_MODULES = [
    'dns_records.py',
    'open_ports.py', 
    'whois_lookup.py',
    'data_leak.py',
    'exposed_env_files.py',
    'pastebin_monitoring.py',
    'shodan.py',
    'subdomain_enum.py',
    'email_harvester.py',
    'subdomain_takeover.py',
    'virustotal_scan.py',
    'content_discovery.py',
    'social_media.py',
    'technology_stack.py'
]

# Findings system check - simplified for modular setup
FINDINGS_ENABLED = False
print("⚠️  Findings system not available: Simplified modular setup")

# Module weight configuration for risk scoring
MODULE_WEIGHTS = {
    "subdomain_takeover.py": 9.0,    # Critical security risk
    "virustotal_scan.py": 8.0,       # Malware detection
    "data_leak.py": 8.5,             # Data breaches
    "exposed_env_files.py": 8.0,     # Configuration exposure
    "content_discovery.py": 7.0,     # Attack surface
    "open_ports.py": 6.0,            # Network exposure
    "shodan.py": 5.5,                # Public exposure
    "subdomain_enum.py": 5.0,        # Attack surface
    "technology_stack.py": 5.0,      # Tech vulnerabilities
    "email_harvester.py": 4.0,       # OSINT risk
    "pastebin_monitoring.py": 6.0,   # Data leaks
    "social_media.py": 3.0,          # OSINT risk
    "dns_records.py": 2.0,           # Reconnaissance
    "whois_lookup.py": 1.0,          # Basic info
}

# Severity multipliers for risk calculation
SEVERITY_MULTIPLIERS = {
    "C": 10.0,  # Critical
    "H": 7.0,   # High
    "W": 4.0,   # Warning
    "I": 1.0,   # Info
    "E": 0.0    # Error
}

# Module metadata for findings
MODULE_METADATA = {
    'dns_records.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'DNS Infrastructure Mapping',
        'description': 'DNS records enumerated for infrastructure analysis',
        'business_impact': 'Infrastructure reconnaissance information',
        'recommendation': 'Review DNS records for security'
    },
    'open_ports.py': {
        'category': 'Attack Surface Expansion', 
        'base_severity': 'high',
        'title': 'Network Port Scanning Results',
        'description': 'Open network ports identified',
        'business_impact': 'Increased attack vectors',
        'recommendation': 'Close unnecessary ports, secure services'
    },
    'subdomain_takeover.py': {
        'category': 'Security Vulnerability',
        'base_severity': 'critical', 
        'title': 'Subdomain Takeover Vulnerabilities',
        'description': 'Subdomain takeover vulnerabilities detected',
        'business_impact': 'Domain hijacking risk',
        'recommendation': 'Remove dangling DNS records immediately'
    },
    'virustotal_scan.py': {
        'category': 'Threat Intelligence',
        'base_severity': 'high',
        'title': 'Malware and Threat Reputation Analysis', 
        'description': 'Domain reputation analysis reveals threats',
        'business_impact': 'Potential malware associations',
        'recommendation': 'Investigate malicious detections'
    },
    'content_discovery.py': {
        'category': 'Attack Surface Expansion',
        'base_severity': 'medium',
        'title': 'Hidden Content and Directories Found',
        'description': 'Administrative interfaces and sensitive directories discovered',
        'business_impact': 'Potential unauthorized access',
        'recommendation': 'Secure exposed content, implement access controls'
    }
}

# Enhanced module categories for frontend
ENHANCED_MODULE_CATEGORIES = {
    "dns_records.py": "Network & Infrastructure",
    "open_ports.py": "Network & Infrastructure", 
    "whois_lookup.py": "Network & Infrastructure",
    "subdomain_enum.py": "Security & Threat Intelligence",
    "email_harvester.py": "Web Application Analysis",
    "social_media.py": "Web Application Analysis",
    "content_discovery.py": "Security & Threat Intelligence",
    "technology_stack.py": "Web Application Analysis",
    "data_leak.py": "Security & Threat Intelligence",
    "exposed_env_files.py": "Security & Threat Intelligence",
    "pastebin_monitoring.py": "Security & Threat Intelligence",
    "shodan.py": "Security & Threat Intelligence",
    "subdomain_takeover.py": "Security & Threat Intelligence",
    "virustotal_scan.py": "Security & Threat Intelligence"
}

# Enhanced module names for frontend
ENHANCED_MODULE_NAMES = {
    "dns_records.py": "DNS Records Check",
    "open_ports.py": "Open Ports Scan",
    "whois_lookup.py": "WHOIS Lookup",
    "subdomain_enum.py": "Subdomain Enumeration",
    "email_harvester.py": "Email Harvesting",
    "social_media.py": "Social Media Presence Scan",
    "content_discovery.py": "Content Discovery",
    "technology_stack.py": "Technology Stack Detection",
    "data_leak.py": "Data Leak Detection",
    "exposed_env_files.py": "Exposed Environment Files",
    "pastebin_monitoring.py": "Pastebin Monitoring",
    "shodan.py": "Shodan Reconnaissance",
    "subdomain_takeover.py": "Subdomain Takeover",
    "virustotal_scan.py": "VirusTotal Scan"
} 