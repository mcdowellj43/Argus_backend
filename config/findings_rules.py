# config/findings_rules.py
"""
Centralized Binary Findings System
Extends the existing findings framework with standardized success/failure evaluation
"""

import re
from typing import Dict, List, Any, Callable, Union

# Severity hierarchy for comparison
SEVERITY_HIERARCHY = {
    "I": 1,    # Info/Informational
    "W": 2,    # Warning/Low
    "M": 3,    # Medium  
    "H": 4,    # High
    "C": 5     # Critical
}

def max_severity(current: str, new: str) -> str:
    """Return the higher severity level"""
    return new if SEVERITY_HIERARCHY.get(new, 0) > SEVERITY_HIERARCHY.get(current, 0) else current

class FindingsRule:
    """Individual rule for severity assessment"""
    def __init__(self, name: str, condition: Callable, severity: str, message: Union[str, Callable], weight: float = 1.0):
        self.name = name
        self.condition = condition
        self.severity = severity
        self.message = message  # Can be string or function
        self.weight = weight
    
    def evaluate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate this rule against scan data"""
        try:
            triggered = self.condition(data)
            
            # Generate dynamic message if message is a function
            if triggered and callable(self.message):
                message = self.message(data)
            elif triggered:
                message = self.message
            else:
                message = None
            
            return {
                "triggered": triggered,
                "severity": self.severity if triggered else None,
                "message": message,
                "rule_name": self.name,
                "weight": self.weight
            }
        except Exception as e:
            return {
                "triggered": False,
                "error": f"Rule evaluation error: {str(e)}",
                "rule_name": self.name
            }

# Centralized findings rules for all modules
FINDINGS_RULES = {
    "dns_records.py": {
        "base_severity": "I",
        "category": "Information Disclosure",
        "title": "DNS Infrastructure Analysis",
        "success_criteria": [
            lambda data: len(data.get("records", [])) > 0,
            lambda data: data.get("status") != "FAILED"
        ],
        "rules": [
            FindingsRule(
                "extensive_records",
                lambda data: len(data.get("records", [])) > 15,
                "W",
                "Extensive DNS record exposure increases reconnaissance value",
                1.5
            ),
            FindingsRule(
                "sensitive_txt_records", 
                lambda data: any(
                    r.get("type") == "TXT" and any(keyword in str(r.get("value", "")).lower() 
                    for keyword in ["spf", "dmarc", "dkim", "verification", "token"])
                    for r in data.get("records", [])
                ),
                "W",
                "Sensitive TXT records found containing SPF/DMARC/verification data",
                1.2
            ),
            FindingsRule(
                "administrative_records",
                lambda data: any(
                    r.get("name", "").lower().startswith(prefix) 
                    for r in data.get("records", [])
                    for prefix in ["admin", "test", "dev", "staging"]
                ),
                "M",
                "Administrative subdomain records discovered",
                2.0
            )
        ]
    },

    "whois_lookup.py": {
        "base_severity": "I", 
        "category": "Information Disclosure",
        "title": "Domain Registration Information",
        "success_criteria": [
            lambda data: bool(data.get("registrar") or data.get("organization")),
            lambda data: data.get("status") != "FAILED"
        ],
        "rules": [
            FindingsRule(
                "privacy_protection_missing",
                lambda data: data.get("organization") and data.get("organization").lower() not in [
                    "redacted for privacy", "private", "whois privacy", "domains by proxy"
                ],
                "W", 
                "Domain registration lacks privacy protection",
                1.0
            ),
            FindingsRule(
                "expiration_soon",
                lambda data: data.get("expires") and "2025" in str(data.get("expires")),
                "M",
                "Domain expiration approaching - potential for takeover",
                1.5
            )
        ]
    },

    "open_ports.py": {
        "base_severity": "M",
        "category": "Attack Surface Expansion", 
        "title": "Open Network Services",
        "success_criteria": [
            lambda data: len(data.get("open_ports", [])) > 0,
            lambda data: data.get("scan_completed", False)
        ],
        "rules": [
            FindingsRule(
                "critical_management_ports",
                lambda data: any(port in [22, 23, 21, 3389, 5900] for port in data.get("open_ports", [])),
                "H",
                "Critical management ports exposed (SSH, Telnet, FTP, RDP, VNC)",
                3.0
            ),
            FindingsRule(
                "database_ports",
                lambda data: any(port in [3306, 5432, 1433, 27017, 6379, 5984] for port in data.get("open_ports", [])),
                "C",
                "Database ports exposed to internet",
                4.0
            ),
            FindingsRule(
                "large_attack_surface",
                lambda data: len(data.get("open_ports", [])) > 10,
                "H",
                lambda data: f"Large attack surface: {len(data.get('open_ports', []))} open ports detected",
                2.5
            ),
            FindingsRule(
                "web_admin_ports",
                lambda data: any(port in [8080, 8443, 9090, 9443, 10000] for port in data.get("open_ports", [])),
                "M",
                "Web administrative interfaces detected",
                2.0
            )
        ]
    },

    "subdomain_enum.py": {
        "base_severity": "W",
        "category": "Attack Surface Expansion",
        "title": "Subdomain Discovery",
        "success_criteria": [
            lambda data: len(data.get("subdomains", [])) > 0,
            lambda data: data.get("status") != "FAILED"
        ],
        "rules": [
            FindingsRule(
                "extensive_subdomains",
                lambda data: len(data.get("subdomains", [])) > 20,
                "M",
                lambda data: f"Large attack surface: {len(data.get('subdomains', []))} subdomains discovered",
                2.0
            ),
            FindingsRule(
                "high_risk_subdomains",
                lambda data: any(
                    any(keyword in sub.lower() for keyword in ["admin", "test", "dev", "staging", "backup"])
                    for sub in data.get("subdomains", [])
                ),
                "H",
                "High-risk administrative subdomains found",
                3.0
            ),
            FindingsRule(
                "active_services",
                lambda data: len([s for s in data.get("subdomains", []) if isinstance(s, dict) and s.get("http_status")]) > 5,
                "M",
                "Multiple active web services discovered",
                1.5
            )
        ]
    },

    "email_harvester.py": {
        "base_severity": "W",
        "category": "Information Disclosure",
        "title": "Email Address Exposure", 
        "success_criteria": [
            lambda data: len(data.get("emails", [])) > 0,
            lambda data: data.get("status") != "FAILED"
        ],
        "rules": [
            FindingsRule(
                "executive_emails",
                lambda data: any(
                    any(keyword in email.lower() for keyword in ["ceo", "cto", "admin", "director"])
                    for email in data.get("emails", [])
                ),
                "M",
                "Executive/administrative email addresses discovered",
                2.0
            ),
            FindingsRule(
                "extensive_email_exposure",
                lambda data: len(data.get("emails", [])) > 10,
                "M",
                lambda data: f"Extensive email exposure: {len(data.get('emails', []))} addresses found",
                1.5
            )
        ]
    },

    "social_media.py": {
        "base_severity": "I",
        "category": "Information Disclosure", 
        "title": "Social Media Profile Discovery",
        "success_criteria": [
            lambda data: len(data.get("profiles", [])) > 0,
            lambda data: data.get("status") != "FAILED"
        ],
        "rules": [
            FindingsRule(
                "business_profiles",
                lambda data: any(
                    p.get("platform", "").lower() in ["linkedin", "github"]
                    for p in data.get("profiles", [])
                ),
                "W",
                "Professional social media profiles identified",
                1.0
            )
        ]
    },

    "content_discovery.py": {
        "base_severity": "M",
        "category": "Attack Surface Expansion",
        "title": "Hidden Content Discovery",
        "success_criteria": [
            lambda data: len(data.get("found_paths", [])) > 0,
            lambda data: data.get("status") != "FAILED"
        ],
        "rules": [
            FindingsRule(
                "admin_interfaces",
                lambda data: any(
                    any(keyword in path.lower() for keyword in ["admin", "administrator", "manage", "dashboard"])
                    for path in data.get("found_paths", [])
                ),
                "H",
                "Administrative interfaces discovered",
                3.0
            ),
            FindingsRule(
                "sensitive_files",
                lambda data: any(
                    path.lower().endswith(ext) for path in data.get("found_paths", [])
                    for ext in [".config", ".env", ".bak", ".sql", ".log"]
                ),
                "H",
                "Sensitive files accessible",
                3.0
            )
        ]
    },

    "technology_stack.py": {
        "base_severity": "W",
        "category": "Information Disclosure",
        "title": "Technology Stack Fingerprinting",
        "success_criteria": [
            lambda data: len(data.get("technologies", [])) > 0,
            lambda data: data.get("status") != "FAILED"
        ],
        "rules": [
            FindingsRule(
                "outdated_technologies",
                lambda data: any(
                    "old" in tech.lower() or "deprecated" in tech.lower()
                    for tech in data.get("technologies", [])
                ),
                "M",
                "Outdated or deprecated technologies detected",
                2.0
            )
        ]
    },

    "shodan.py": {
        "base_severity": "H",
        "category": "Threat Intelligence",
        "title": "Internet-Connected Device Discovery",
        "success_criteria": [
            lambda data: len(data.get("results", [])) > 0,
            lambda data: data.get("status") != "FAILED"
        ],
        "rules": [
            FindingsRule(
                "vulnerable_services",
                lambda data: any(
                    "vulnerability" in str(result).lower() or "exploit" in str(result).lower()
                    for result in data.get("results", [])
                ),
                "C",
                "Vulnerable services identified via Shodan",
                4.0
            ),
            FindingsRule(
                "industrial_systems",
                lambda data: any(
                    any(keyword in str(result).lower() for keyword in ["scada", "plc", "ics", "modbus"])
                    for result in data.get("results", [])
                ),
                "C",
                "Industrial control systems exposed",
                4.0
            )
        ]
    },

    "exposed_env_files.py": {
        "base_severity": "C",
        "category": "Critical Exposure",
        "title": "Configuration File Exposure",
        "success_criteria": [
            lambda data: data.get("scan_completed", False)
        ],
        "rules": [
            FindingsRule(
                "accessible_files",
                lambda data: len(data.get("accessible_files", [])) > 0,
                "C",
                "Environment files publicly accessible",
                5.0
            ),
            FindingsRule(
                "credentials_exposed",
                lambda data: any(
                    len(f.get("analysis", {}).get("sensitive_items", [])) > 0
                    for f in data.get("accessible_files", [])
                ),
                "C",
                "Credentials and secrets exposed in configuration files",
                5.0
            )
        ]
    },

    "subdomain_takeover.py": {
        "base_severity": "H",
        "category": "Critical Exposure",
        "title": "Subdomain Takeover Vulnerabilities",
        "success_criteria": [
            lambda data: data.get("scan_completed", False)
        ],
        "rules": [
            FindingsRule(
                "takeover_possible",
                lambda data: len(data.get("vulnerable_subdomains", [])) > 0,
                "C",
                "Subdomain takeover vulnerabilities detected",
                4.0
            )
        ]
    },

    "virustotal_scan.py": {
        "base_severity": "M",
        "category": "Threat Intelligence", 
        "title": "Reputation Analysis",
        "success_criteria": [
            lambda data: data.get("scan_completed", False)
        ],
        "rules": [
            FindingsRule(
                "malicious_detections",
                lambda data: data.get("malicious_count", 0) > 0,
                "C",
                lambda data: f"Malicious detections: {data.get('malicious_count', 0)} engines flagged domain",
                4.0
            ),
            FindingsRule(
                "suspicious_detections", 
                lambda data: data.get("suspicious_count", 0) > 2,
                "H",
                lambda data: f"Multiple suspicious detections: {data.get('suspicious_count', 0)} engines",
                2.5
            )
        ]
    },

    "pastebin_monitoring.py": {
        "base_severity": "H",
        "category": "Data Leakage",
        "title": "Paste Site Monitoring",
        "success_criteria": [
            lambda data: data.get("scan_completed", False)
        ],
        "rules": [
            FindingsRule(
                "data_found",
                lambda data: len(data.get("pastes_found", [])) > 0,
                "H",
                "Organizational data found on paste sites",
                3.0
            ),
            FindingsRule(
                "credentials_leaked",
                lambda data: any(
                    any(keyword in paste.get("content", "").lower() for keyword in ["password", "api_key", "token"])
                    for paste in data.get("pastes_found", [])
                ),
                "C",
                "Credentials potentially leaked on paste sites",
                4.0
            )
        ]
    }
}

def evaluate_findings(module_name: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate findings for a specific module
    
    Args:
        module_name: Name of the module (e.g., "dns_records.py")
        scan_data: Raw scan data from the module
    
    Returns:
        Standardized findings result with success/failure and severity
    """
    
    # Get module rules or use defaults
    module_rules = FINDINGS_RULES.get(module_name, {
        "base_severity": "I",
        "category": "Unknown",
        "title": "Security Assessment",
        "success_criteria": [lambda data: data.get("status") != "FAILED"],
        "rules": []
    })
    
    # Check success criteria
    success = True
    for criterion in module_rules.get("success_criteria", []):
        try:
            if not criterion(scan_data):
                success = False
                break
        except Exception:
            success = False
            break
    
    # Evaluate all rules
    triggered_rules = []
    current_severity = module_rules["base_severity"]
    total_weight = 0
    
    for rule in module_rules.get("rules", []):
        result = rule.evaluate(scan_data)
        if result.get("triggered"):
            triggered_rules.append(result)
            current_severity = max_severity(current_severity, result["severity"])
            total_weight += result.get("weight", 1.0)
    
    # Generate findings summary
    findings_messages = [r["message"] for r in triggered_rules if r.get("message")]
    
    return {
        "success": success,
        "severity": current_severity,
        "category": module_rules["category"],
        "title": module_rules["title"],
        "findings": findings_messages,
        "findings_count": len(findings_messages),
        "rules_triggered": len(triggered_rules),
        "total_weight": total_weight,
        "base_severity": module_rules["base_severity"],
        "has_findings": len(findings_messages) > 0,
        "module_name": module_name
    }

def display_findings_result(scan_data: Dict[str, Any], findings_result: Dict[str, Any]):
    """Display findings in a standardized, terminal-safe format"""
    
    # Use simple text indicators instead of special characters
    status_text = "SUCCESS" if findings_result["success"] else "FAILED"
    severity = findings_result["severity"]
    
    print(f"[{severity}] {severity_to_text(severity)}: {findings_result['title']}")
    print(f"[I] Status: {status_text}")
    
    if findings_result["findings"]:
        print(f"[I] Findings ({findings_result['findings_count']}):")
        for finding in findings_result["findings"]:
            print(f"    - {finding}")  # Use simple dash instead of bullet
    else:
        print("[I] No security findings detected")
    
    print(f"[I] Category: {findings_result['category']}")
    print(f"[I] Risk Weight: {findings_result.get('total_weight', 0):.1f}")

def severity_to_text(severity: str) -> str:
    """Convert severity code to full text"""
    severity_map = {
        "C": "CRITICAL",
        "H": "HIGH", 
        "M": "MEDIUM",
        "W": "WARNING",
        "I": "INFO"
    }
    return severity_map.get(severity, "UNKNOWN")

# Utility functions for integration
def get_severity_color(severity: str) -> str:
    """Get color code for severity display (optional, for terminals that support it)"""
    colors = {
        "C": "\033[91m",  # Red
        "H": "\033[93m",  # Yellow  
        "M": "\033[94m",  # Blue
        "W": "\033[95m",  # Magenta
        "I": "\033[96m"   # Cyan
    }
    reset = "\033[0m"     # Reset
    # Only return colors if explicitly enabled, otherwise return empty string
    return ""  # Disabled by default for terminal compatibility

def get_severity_score(severity: str) -> int:
    """Convert severity to numeric score for calculations"""
    return SEVERITY_HIERARCHY.get(severity, 0)

def calculate_module_risk_score(findings_result: Dict[str, Any]) -> float:
    """Calculate risk score for a module based on findings"""
    base_score = get_severity_score(findings_result.get("base_severity", "I"))
    current_score = get_severity_score(findings_result.get("severity", "I"))
    weight = findings_result.get("total_weight", 0)
    
    # Risk score = base + severity bump + weight factor
    risk_score = base_score + (current_score - base_score) * 1.5 + (weight * 0.5)
    return min(risk_score, 10.0)  # Cap is 10