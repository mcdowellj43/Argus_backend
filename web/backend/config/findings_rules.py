#!/usr/bin/env python3
"""
Centralized Binary Findings System - Core Rules Engine
This module provides the evaluate_findings and display_findings_result functions
that are imported by all 14 enhanced modules.
"""

import sys
from datetime import datetime

try:
    from .findings_config import (
        get_module_rules, get_thresholds, get_risk_weights,
        get_severity_levels, get_category_mapping
    )
except ImportError:
    # Fallback configuration if config file not available
    def get_module_rules(module_name):
        return {}
    def get_thresholds():
        return {}
    def get_risk_weights():
        return {}
    def get_severity_levels():
        return {"C": "Critical", "H": "High", "W": "Warning", "I": "Info", "E": "Error"}
    def get_category_mapping():
        return {}

def evaluate_findings(module_name, scan_data):
    """
    Main findings evaluation function used by all enhanced modules
    
    Args:
        module_name (str): Name of the module (e.g., "dns_records.py")
        scan_data (dict): Scan results from the module
        
    Returns:
        dict: Standardized findings result
    """
    try:
        # Get module-specific rules
        rules = get_module_rules(module_name)
        thresholds = get_thresholds()
        
        # Initialize findings result
        findings_result = {
            "success": True,
            "severity": "I",
            "category": "General",
            "title": "Security Assessment", 
            "findings": [],
            "findings_count": 0,
            "has_findings": False,
            "total_weight": 0.0
        }
        
        # Module-specific evaluation logic
        if module_name == "dns_records.py":
            findings_result = evaluate_dns_records(scan_data, rules, thresholds)
        elif module_name == "open_ports.py":
            findings_result = evaluate_open_ports(scan_data, rules, thresholds)
        elif module_name == "whois_lookup.py":
            findings_result = evaluate_whois_lookup(scan_data, rules, thresholds)
        elif module_name == "subdomain_takeover.py":
            findings_result = evaluate_subdomain_takeover(scan_data, rules, thresholds)
        elif module_name == "virustotal_scan.py":
            findings_result = evaluate_virustotal_scan(scan_data, rules, thresholds)
        elif module_name == "content_discovery.py":
            findings_result = evaluate_content_discovery(scan_data, rules, thresholds)
        elif module_name == "social_media.py":
            findings_result = evaluate_social_media(scan_data, rules, thresholds)
        elif module_name == "technology_stack.py":
            findings_result = evaluate_technology_stack(scan_data, rules, thresholds)
        elif module_name == "data_leak.py":
            findings_result = evaluate_data_leak(scan_data, rules, thresholds)
        elif module_name == "exposed_env_files.py":
            findings_result = evaluate_exposed_env_files(scan_data, rules, thresholds)
        elif module_name == "pastebin_monitoring.py":
            findings_result = evaluate_pastebin_monitoring(scan_data, rules, thresholds)
        elif module_name == "shodan.py":
            findings_result = evaluate_shodan(scan_data, rules, thresholds)
        elif module_name == "subdomain_enum.py":
            findings_result = evaluate_subdomain_enum(scan_data, rules, thresholds)
        elif module_name == "email_harvester.py":
            findings_result = evaluate_email_harvester(scan_data, rules, thresholds)
        else:
            # Generic evaluation for unknown modules
            findings_result = evaluate_generic_module(scan_data, rules, thresholds)
        
        # Set category and title from mapping
        category_mapping = get_category_mapping()
        module_info = category_mapping.get(module_name, {})
        findings_result["category"] = module_info.get("category", "General")
        findings_result["title"] = module_info.get("title", "Security Assessment")
        
        return findings_result
        
    except Exception as e:
        # Return safe fallback on error
        return {
            "success": False,
            "severity": "E",
            "category": "Error",
            "title": "Evaluation Error",
            "findings": [f"Error evaluating findings: {str(e)}"],
            "findings_count": 0,
            "has_findings": True,
            "total_weight": 0.0
        }

def display_findings_result(scan_data, findings_result):
    """
    Display findings result in standardized format
    Used by all enhanced modules for consistent output
    """
    try:
        target = scan_data.get("target", "Unknown")
        severity = findings_result.get("severity", "I")
        title = findings_result.get("title", "Security Assessment")
        category = findings_result.get("category", "General")
        findings = findings_result.get("findings", [])
        
        # Display header
        print()
        print(f"[{severity}] {severity_text(severity)}: {title}")
        print(f"[I] Status: {'SUCCESS' if findings_result.get('success') else 'FAILED'}")
        
        # Display findings
        if findings:
            print(f"[I] Findings ({len(findings)}):")
            for finding in findings:
                print(f"    • {finding}")
        else:
            print("[I] No significant findings detected")
        
        print(f"[I] Category: {category}")
        
        # Display risk weight if available
        risk_weight = findings_result.get("total_weight", 0)
        if risk_weight > 0:
            print(f"[I] Risk Weight: {risk_weight}")
        
    except Exception as e:
        print(f"[E] Error displaying findings: {str(e)}")

def severity_text(severity):
    """Convert severity code to descriptive text"""
    severity_map = {
        "C": "CRITICAL",
        "H": "HIGH", 
        "W": "WARNING",
        "I": "INFO",
        "E": "ERROR"
    }
    return severity_map.get(severity, "UNKNOWN")

# =============================================================================
# MODULE-SPECIFIC EVALUATION FUNCTIONS
# =============================================================================

def evaluate_dns_records(scan_data, rules, thresholds):
    """Evaluate DNS records findings"""
    records = scan_data.get("records", [])
    record_count = len(records)
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if record_count > thresholds.get("dns_high_record_count", 10):
        severity = "W"
        weight += 2.5
        findings.append(f"Extensive DNS record exposure increases reconnaissance value ({record_count} records)")
    
    # Check for sensitive TXT records
    txt_records = [r for r in records if r.get("type") == "TXT"]
    if txt_records:
        weight += 1.0
        findings.append(f"Sensitive TXT records found containing SPF/DMARC/verification data ({len(txt_records)} records)")
    
    return {
        "success": record_count > 0,
        "severity": severity,
        "category": "Network & Infrastructure",
        "title": "DNS Infrastructure Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_open_ports(scan_data, rules, thresholds):
    """Evaluate open ports findings"""
    open_ports = scan_data.get("open_ports", [])
    port_count = len(open_ports)
    
    findings = []
    severity = "I"
    weight = 0.0
    
    # Critical ports check
    critical_ports = {22: "SSH", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis"}
    critical_found = [port for port in open_ports if port in critical_ports]
    
    if critical_found:
        severity = "H"
        weight += 7.0
        findings.append(f"Critical service ports exposed: {', '.join(f'{p} ({critical_ports[p]})' for p in critical_found)}")
    
    if port_count > thresholds.get("port_high_count", 10):
        if severity != "H":
            severity = "W"
        weight += 3.0
        findings.append(f"High number of open ports increases attack surface ({port_count} ports)")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Attack Surface Expansion",
        "title": "Network Port Scanning Results",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_whois_lookup(scan_data, rules, thresholds):
    """Evaluate WHOIS lookup findings"""
    findings = []
    severity = "I"
    weight = 0.0
    
    # Check for privacy protection
    if not scan_data.get("privacy_protected", False):
        severity = "W"
        weight += 2.0
        findings.append("Domain registration details exposed (no privacy protection)")
    
    # Check expiration date
    days_until_expiry = scan_data.get("days_until_expiry", 365)
    if days_until_expiry < 30:
        severity = "W"
        weight += 1.5
        findings.append(f"Domain expires soon ({days_until_expiry} days)")
    
    return {
        "success": scan_data.get("status") == "SUCCESS",
        "severity": severity,
        "category": "Network & Infrastructure", 
        "title": "Domain Registration Information",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_subdomain_takeover(scan_data, rules, thresholds):
    """Evaluate subdomain takeover findings"""
    vulnerable_subdomains = scan_data.get("vulnerable_subdomains", [])
    potentially_vulnerable = scan_data.get("potentially_vulnerable", [])
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if vulnerable_subdomains:
        severity = "C"
        weight += 9.5
        findings.append(f"Critical subdomain takeover vulnerabilities detected ({len(vulnerable_subdomains)} subdomains)")
        findings.append("Immediate action required to prevent domain hijacking")
    
    if potentially_vulnerable:
        if severity != "C":
            severity = "W"
        weight += 4.0
        findings.append(f"Potentially vulnerable subdomains require manual verification ({len(potentially_vulnerable)} subdomains)")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Security Vulnerability",
        "title": "Subdomain Takeover Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_virustotal_scan(scan_data, rules, thresholds):
    """Evaluate VirusTotal scan findings"""
    malicious_count = scan_data.get("malicious_count", 0)
    suspicious_count = scan_data.get("suspicious_count", 0)
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if malicious_count > 0:
        severity = "C"
        weight += 8.5
        findings.append(f"Malware signatures detected by {malicious_count} security engines")
        findings.append("Domain may be associated with malicious infrastructure")
    
    if suspicious_count > 0:
        if severity != "C":
            severity = "W"
        weight += 3.5
        findings.append(f"Suspicious activity reported by {suspicious_count} security engines")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Threat Intelligence",
        "title": "Malware and Threat Reputation Analysis", 
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_content_discovery(scan_data, rules, thresholds):
    """Evaluate content discovery findings"""
    found_paths = scan_data.get("found_paths", [])
    admin_interfaces = scan_data.get("admin_interfaces", [])
    sensitive_files = scan_data.get("sensitive_files", [])
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if sensitive_files:
        severity = "C"
        weight += 7.5
        findings.append(f"Critical configuration files exposed ({len(sensitive_files)} files)")
        findings.append("Sensitive information disclosure may compromise security")
    
    if admin_interfaces:
        if severity != "C":
            severity = "H"
        weight += 5.0
        findings.append(f"Administrative interfaces discovered ({len(admin_interfaces)} interfaces)")
    
    if len(found_paths) > thresholds.get("content_high_exposure", 15):
        if severity not in ["C", "H"]:
            severity = "W"
        weight += 2.5
        findings.append(f"High content exposure increases attack surface ({len(found_paths)} paths)")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Attack Surface Expansion",
        "title": "Hidden Content and Directories Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_social_media(scan_data, rules, thresholds):
    """Evaluate social media findings"""
    profiles = scan_data.get("profiles", [])
    business_platforms = scan_data.get("business_platforms", [])
    personal_platforms = scan_data.get("personal_platforms", [])
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if len(profiles) >= 8:
        severity = "W"
        weight += 3.5
        findings.append(f"High social media exposure across {len(profiles)} profiles")
        findings.append("Extensive OSINT profile enables comprehensive reconnaissance")
    
    if business_platforms and personal_platforms:
        if severity != "W":
            severity = "W"
        weight += 2.0
        findings.append("Professional and personal platforms linked (correlation risk)")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Web Application Analysis",
        "title": "Social Media Integration Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_technology_stack(scan_data, rules, thresholds):
    """Evaluate technology stack findings"""
    outdated_tech = scan_data.get("outdated_tech", [])
    deprecated_tech = scan_data.get("deprecated_tech", [])
    security_headers = scan_data.get("security_headers", [])
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if outdated_tech:
        severity = "W"
        weight += 4.5
        findings.append(f"Outdated technologies detected: {', '.join(outdated_tech)}")
        findings.append("Version vulnerabilities may exist in legacy components")
    
    if len(security_headers) < 3:
        if severity != "W":
            severity = "W"
        weight += 2.0
        findings.append("Missing critical security headers expose application to attacks")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Web Application Analysis",
        "title": "Technology Stack Security Assessment",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_data_leak(scan_data, rules, thresholds):
    """Evaluate data leak findings"""
    # Implementation would depend on data_leak.py structure
    findings = []
    severity = "I"
    weight = 0.0
    
    # Generic evaluation based on common data leak patterns
    breaches_found = scan_data.get("breaches_found", 0)
    if breaches_found > 0:
        severity = "C"
        weight += 9.0
        findings.append(f"Data breaches identified affecting {breaches_found} accounts")
        findings.append("Personal information may be exposed in public databases")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Data Protection",
        "title": "Data Breach Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_exposed_env_files(scan_data, rules, thresholds):
    """Evaluate exposed environment files findings"""
    accessible_files = scan_data.get("accessible_files", [])
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if accessible_files:
        severity = "C"
        weight += 8.5
        findings.append(f"Critical environment files exposed ({len(accessible_files)} files)")
        findings.append("Configuration secrets and credentials may be compromised")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Security Vulnerability",
        "title": "Environment File Exposure Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_pastebin_monitoring(scan_data, rules, thresholds):
    """Evaluate pastebin monitoring findings"""
    pastes_found = scan_data.get("pastes_found", [])
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if pastes_found:
        severity = "H"
        weight += 6.5
        findings.append(f"Data exposure detected in public paste sites ({len(pastes_found)} instances)")
        findings.append("Sensitive information may be publicly accessible")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Data Protection",
        "title": "Public Data Exposure Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_shodan(scan_data, rules, thresholds):
    """Evaluate Shodan scan findings"""
    # Implementation would depend on shodan.py structure
    findings = []
    severity = "I"
    weight = 0.0
    
    # Generic evaluation based on common Shodan patterns
    services_found = scan_data.get("services", [])
    if len(services_found) > 5:
        severity = "W"
        weight += 4.0
        findings.append(f"Multiple network services publicly exposed ({len(services_found)} services)")
        findings.append("Increased attack surface requires security review")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Attack Surface Expansion",
        "title": "Public Service Exposure Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_subdomain_enum(scan_data, rules, thresholds):
    """Evaluate subdomain enumeration findings"""
    subdomains = scan_data.get("subdomains", [])
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if len(subdomains) > thresholds.get("subdomain_high_count", 20):
        severity = "W"
        weight += 3.0
        findings.append(f"Extensive subdomain exposure increases attack surface ({len(subdomains)} subdomains)")
        findings.append("Large subdomain footprint requires comprehensive security management")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Attack Surface Expansion",
        "title": "Subdomain Enumeration Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_email_harvester(scan_data, rules, thresholds):
    """Evaluate email harvester findings"""
    emails = scan_data.get("emails", [])
    
    findings = []
    severity = "I"
    weight = 0.0
    
    if len(emails) > thresholds.get("email_high_count", 10):
        severity = "W"
        weight += 2.5
        findings.append(f"Extensive email exposure increases phishing risk ({len(emails)} emails)")
        findings.append("Email addresses may be targeted for social engineering attacks")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "Data Protection",
        "title": "Email Address Exposure Analysis",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }

def evaluate_generic_module(scan_data, rules, thresholds):
    """Generic evaluation for unknown modules"""
    findings = []
    severity = "I"
    weight = 0.0
    
    # Basic evaluation based on scan completion
    if scan_data.get("scan_completed", False):
        findings.append("Security assessment completed successfully")
    else:
        severity = "W"
        findings.append("Security assessment completed with limitations")
    
    return {
        "success": scan_data.get("scan_completed", False),
        "severity": severity,
        "category": "General",
        "title": "Security Assessment",
        "findings": findings,
        "findings_count": len(findings),
        "has_findings": len(findings) > 0,
        "total_weight": weight
    }