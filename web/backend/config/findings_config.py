#!/usr/bin/env python3
"""
Centralized Binary Findings System - Configuration Management
Provides thresholds, weights, and category mappings for the findings system
"""

def get_module_rules(module_name):
    """Get specific rules for a module"""
    rules = {
        "dns_records.py": {
            "high_record_threshold": 10,
            "sensitive_txt_check": True
        },
        "open_ports.py": {
            "critical_ports": [22, 3306, 5432, 6379, 1433, 27017],
            "high_port_threshold": 10
        },
        "subdomain_takeover.py": {
            "critical_services": ["GitHub Pages", "AWS S3", "Heroku"],
            "risk_threshold": "MEDIUM"
        },
        "virustotal_scan.py": {
            "malicious_threshold": 1,
            "suspicious_threshold": 3
        },
        "content_discovery.py": {
            "critical_paths": ["/.env", "/.git", "/config", "/backup"],
            "admin_paths": ["/admin", "/wp-admin", "/dashboard"]
        }
    }
    return rules.get(module_name, {})

def get_thresholds():
    """Get detection thresholds"""
    return {
        # DNS Records
        "dns_high_record_count": 10,
        "dns_txt_sensitivity": True,
        
        # Open Ports
        "port_high_count": 10,
        "port_critical_services": [22, 3306, 5432, 6379],
        
        # Subdomains
        "subdomain_high_count": 20,
        "subdomain_admin_patterns": ["admin", "test", "dev"],
        
        # Email Harvesting
        "email_high_count": 10,
        "email_executive_patterns": ["ceo", "admin", "director"],
        
        # Social Media
        "social_high_platform_count": 8,
        "social_high_profile_count": 15,
        
        # Content Discovery
        "content_high_exposure": 15,
        "content_admin_threshold": 3,
        
        # Technology Stack
        "tech_outdated_threshold": 2,
        "tech_missing_headers_threshold": 3,
        
        # Data Leaks
        "data_leak_critical_threshold": 1,
        "data_leak_warning_threshold": 5,
        
        # Environment Files
        "env_file_critical_threshold": 1,
        
        # Pastebin
        "pastebin_exposure_threshold": 1,
        
        # Shodan
        "shodan_service_threshold": 5,
        "shodan_vuln_threshold": 1,
        
        # VirusTotal
        "vt_malicious_threshold": 1,
        "vt_suspicious_threshold": 3
    }

def get_risk_weights():
    """Get risk weight multipliers for different finding types"""
    return {
        # Critical Security Issues
        "subdomain_takeover": 9.5,
        "data_breach": 9.0,
        "malware_detection": 8.5,
        "env_file_exposure": 8.5,
        "credential_exposure": 8.0,
        
        # High Risk Issues
        "admin_interface_exposure": 7.0,
        "critical_port_exposure": 7.0,
        "config_file_exposure": 6.5,
        "pastebin_exposure": 6.0,
        
        # Medium Risk Issues
        "high_port_count": 4.0,
        "extensive_subdomain_exposure": 3.5,
        "social_media_correlation": 3.0,
        "outdated_technology": 4.5,
        
        # Low Risk Issues
        "dns_information_disclosure": 2.0,
        "email_exposure": 2.5,
        "basic_reconnaissance": 1.5,
        "whois_disclosure": 1.0
    }

def get_severity_levels():
    """Get severity level definitions"""
    return {
        "C": {
            "name": "Critical",
            "description": "Immediate security risk requiring urgent action",
            "weight_range": (8.0, 10.0),
            "examples": ["Subdomain takeover", "Data breaches", "Malware detection"]
        },
        "H": {
            "name": "High", 
            "description": "Significant security risk requiring prompt attention",
            "weight_range": (6.0, 7.9),
            "examples": ["Admin interface exposure", "Critical port exposure"]
        },
        "W": {
            "name": "Warning",
            "description": "Moderate security concern requiring review",
            "weight_range": (3.0, 5.9),
            "examples": ["High port count", "Outdated technology", "Social media exposure"]
        },
        "I": {
            "name": "Info",
            "description": "Informational finding for security awareness",
            "weight_range": (0.0, 2.9),
            "examples": ["DNS records", "WHOIS information", "Basic reconnaissance"]
        },
        "E": {
            "name": "Error",
            "description": "Assessment error or incomplete scan",
            "weight_range": (0.0, 0.0),
            "examples": ["Scan failures", "API errors", "Timeout issues"]
        }
    }

def get_category_mapping():
    """Get category mappings for findings"""
    return {
        # Network & Infrastructure
        "dns_records.py": {
            "category": "Network & Infrastructure",
            "title": "DNS Infrastructure Analysis",
            "base_severity": "low"
        },
        "whois_lookup.py": {
            "category": "Network & Infrastructure", 
            "title": "Domain Registration Information",
            "base_severity": "low"
        },
        "open_ports.py": {
            "category": "Attack Surface Expansion",
            "title": "Network Port Scanning Results", 
            "base_severity": "high"
        },
        
        # Security Vulnerabilities
        "subdomain_takeover.py": {
            "category": "Security Vulnerability",
            "title": "Subdomain Takeover Analysis",
            "base_severity": "critical"
        },
        "exposed_env_files.py": {
            "category": "Security Vulnerability",
            "title": "Environment File Exposure Analysis",
            "base_severity": "critical"
        },
        
        # Threat Intelligence
        "virustotal_scan.py": {
            "category": "Threat Intelligence",
            "title": "Malware and Threat Reputation Analysis",
            "base_severity": "high"
        },
        "shodan.py": {
            "category": "Threat Intelligence", 
            "title": "Public Service Exposure Analysis",
            "base_severity": "medium"
        },
        
        # Attack Surface Expansion
        "content_discovery.py": {
            "category": "Attack Surface Expansion",
            "title": "Hidden Content and Directories Analysis",
            "base_severity": "medium"
        },
        "subdomain_enum.py": {
            "category": "Attack Surface Expansion",
            "title": "Subdomain Enumeration Analysis", 
            "base_severity": "medium"
        },
        
        # Web Application Analysis
        "technology_stack.py": {
            "category": "Web Application Analysis",
            "title": "Technology Stack Security Assessment",
            "base_severity": "medium"
        },
        "social_media.py": {
            "category": "Web Application Analysis",
            "title": "Social Media Integration Analysis",
            "base_severity": "low"
        },
        
        # Data Protection
        "data_leak.py": {
            "category": "Data Protection",
            "title": "Data Breach Analysis",
            "base_severity": "critical"
        },
        "email_harvester.py": {
            "category": "Data Protection",
            "title": "Email Address Exposure Analysis",
            "base_severity": "medium"
        },
        "pastebin_monitoring.py": {
            "category": "Data Protection",
            "title": "Public Data Exposure Analysis",
            "base_severity": "high"
        }
    }

def get_environment_weights():
    """Get environment-specific weight adjustments"""
    return {
        "production": {
            "multiplier": 1.2,
            "description": "Production environments have higher risk impact"
        },
        "staging": {
            "multiplier": 0.8,
            "description": "Staging environments have moderate risk impact"  
        },
        "development": {
            "multiplier": 0.6,
            "description": "Development environments have lower risk impact"
        },
        "testing": {
            "multiplier": 0.5,
            "description": "Testing environments have minimal risk impact"
        }
    }

def get_risk_keywords():
    """Get risk keyword definitions for enhanced analysis"""
    return {
        "critical_keywords": [
            "password", "secret", "key", "token", "credential", 
            "private", "confidential", "admin", "root"
        ],
        "high_risk_keywords": [
            "database", "backup", "config", "env", "settings",
            "user", "login", "auth", "session"
        ],
        "medium_risk_keywords": [
            "api", "endpoint", "service", "internal", "dev",
            "test", "staging", "debug"
        ]
    }

def get_display_settings():
    """Get display and output formatting settings"""
    return {
        "max_findings_display": 10,
        "truncate_long_outputs": True,
        "max_output_length": 500,
        "show_risk_weights": True,
        "show_categories": True,
        "use_colors": False,  # Disabled for terminal compatibility
        "severity_indicators": {
            "C": "[C]",
            "H": "[H]", 
            "W": "[W]",
            "I": "[I]",
            "E": "[E]"
        }
    }

def get_reporting_settings():
    """Get settings for report generation"""
    return {
        "include_technical_details": True,
        "include_remediation_steps": True,
        "include_risk_scores": True,
        "group_by_severity": True,
        "group_by_category": True,
        "max_evidence_length": 1000,
        "include_scan_metadata": True
    }