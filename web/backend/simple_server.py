#!/usr/bin/env python3
"""
Enhanced Argus Web Server - With Clean Script Integration & Report Generation
Supports clean module outputs and frontend template integration
"""

import http.server
import socketserver
import json
import urllib.parse
import uuid
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path
import threading
import time
import importlib.util

# Import the findings system
try:
    from modules.findings_generator import FindingsGenerator
    from modules.risk_calculator import RiskCalculator
    FINDINGS_ENABLED = True
    print("✅ Findings system loaded successfully")
except ImportError as e:
    print(f"⚠️  Findings system not available: {e}")
    FINDINGS_ENABLED = False

# Module-specific timeout configuration (in seconds)
MODULE_TIMEOUTS = {
    'data_leak.py': 1200,              # 20 minutes - API rate limited
    'subdomain_enum.py': 180,         # 3 minutes - DNS enumeration
    'subdomain_takeover.py': 240,     # 4 minutes - comprehensive testing
    'virustotal_scan.py': 120,        # 2 minutes - API dependent
    'email_harvester.py': 300,        # 5 minutes - comprehensive search
    'shodan.py': 180,                 # 3 minutes - API dependent
    'censys.py': 180,                 # 3 minutes - API dependent
    'default': 60                     # 1 minute for all other modules
}

def get_module_timeout(module_script):
    """Get timeout for specific module, fallback to default"""
    return MODULE_TIMEOUTS.get(module_script, MODULE_TIMEOUTS['default'])

# Configuration
PORT = 8000
HOST = "localhost"

# Add the Argus root directory to Python path
current_dir = Path.cwd()
argus_root = current_dir.parent.parent  # Go up from web/backend to argus root
sys.path.insert(0, str(argus_root))

print(f"📁 Current directory: {current_dir}")
print(f"📁 Argus root directory: {argus_root}")

# Simple in-memory storage
active_scans = {}
scan_history = {}

# =============================================================================
# ENHANCED DATA FORMATTING FOR FRONTEND TEMPLATES
# =============================================================================

def get_finding_metadata(module_name):
    """Get metadata for findings from specific modules"""
    metadata = {
        "dns_records.py": {
            "title": "DNS Infrastructure Analysis",
            "category": "Information Disclosure",
            "severity_base": "LOW",
            "description": "DNS records enumerated revealing infrastructure components",
            "business_impact": "Infrastructure reconnaissance information",
            "recommendation": "Review DNS records for unnecessary information disclosure"
        },
        "open_ports.py": {
            "title": "Open Network Services Detected", 
            "category": "Attack Surface Expansion",
            "severity_base": "MEDIUM",
            "description": "Network services accessible from the internet",
            "business_impact": "Increased attack vectors and potential unauthorized access",
            "recommendation": "Review necessity of all open ports and close unnecessary services"
        },
        "whois_lookup.py": {
            "title": "Domain Registration Information",
            "category": "Information Disclosure", 
            "severity_base": "LOW",
            "description": "Domain registration details collected from WHOIS databases",
            "business_impact": "Organizational information disclosure",
            "recommendation": "Consider domain privacy protection where appropriate"
        },
        "content_discovery.py": {
            "title": "Hidden Content Discovery",
            "category": "Attack Surface Expansion",
            "severity_base": "MEDIUM", 
            "description": "Administrative interfaces or sensitive directories discovered",
            "business_impact": "Potential access to administrative functions",
            "recommendation": "Secure or remove unnecessary exposed content"
        },
        "email_harvester.py": {
            "title": "Email Address Exposure",
            "category": "Information Disclosure",
            "severity_base": "LOW",
            "description": "Employee email addresses discoverable through public sources",
            "business_impact": "Increased susceptibility to phishing attacks",
            "recommendation": "Implement email obfuscation techniques"
        },
        "social_media.py": {
            "title": "Social Media Profile Discovery",
            "category": "Information Disclosure",
            "severity_base": "LOW",
            "description": "Social media profiles linked to the organization discovered",
            "business_impact": "Additional reconnaissance information for attackers",
            "recommendation": "Review social media presence and privacy settings"
        },
        "technology_stack.py": {
            "title": "Technology Stack Fingerprinting",
            "category": "Information Disclosure",
            "severity_base": "LOW",
            "description": "Web application technology stack identified",
            "business_impact": "Technology disclosure enabling targeted attacks",
            "recommendation": "Implement technology obfuscation and keep software updated"
        },
        "data_leak.py": {
            "title": "Data Breach Exposure",
            "category": "Critical Exposure",
            "severity_base": "CRITICAL",
            "description": "Email addresses or credentials found in known data breaches",
            "business_impact": "Direct data breach risk and potential unauthorized access",
            "recommendation": "Implement continuous breach monitoring and mandate password resets"
        },
        "exposed_env_files.py": {
            "title": "Configuration File Exposure",
            "category": "Critical Exposure", 
            "severity_base": "CRITICAL",
            "description": "Environment files containing sensitive information publicly accessible",
            "business_impact": "Direct exposure of secrets and credentials",
            "recommendation": "Immediately remove exposed files and rotate secrets"
        },
        "pastebin_monitoring.py": {
            "title": "Paste Site Monitoring",
            "category": "Data Leakage",
            "severity_base": "HIGH",
            "description": "Organizational data identified on public paste sites",
            "business_impact": "Sensitive information publicly available",
            "recommendation": "Monitor paste sites continuously and investigate source"
        },
        "shodan.py": {
            "title": "Internet Device Reconnaissance", 
            "category": "Attack Surface Expansion",
            "severity_base": "HIGH",
            "description": "Internet-connected devices and services discovered",
            "business_impact": "Discovery of exposed services and potential vulnerabilities",
            "recommendation": "Audit all discovered assets and ensure proper security controls"
        },
        "subdomain_enum.py": {
            "title": "Subdomain Discovery",
            "category": "Attack Surface Expansion",
            "severity_base": "HIGH", 
            "description": "Additional subdomains identified expanding attack surface",
            "business_impact": "Increased attack surface and potential forgotten services",
            "recommendation": "Audit all discovered subdomains and ensure consistent security"
        },
        "subdomain_takeover.py": {
            "title": "Subdomain Takeover Vulnerability",
            "category": "Critical Vulnerability",
            "severity_base": "CRITICAL",
            "description": "Subdomains vulnerable to takeover attacks detected",
            "business_impact": "Complete subdomain compromise potential",
            "recommendation": "Immediately remove dangling DNS records"
        },
        "virustotal_scan.py": {
            "title": "Malware and Reputation Scan",
            "category": "Threat Intelligence",
            "severity_base": "HIGH",
            "description": "Domain or URL reputation analysis completed",
            "business_impact": "Reputation-based risks and potential malware association", 
            "recommendation": "Monitor reputation continuously and address issues promptly"
        }
    }
    
    return metadata.get(module_name, {
        "title": module_name.replace('.py', '').replace('_', ' ').title(),
        "category": "General Security",
        "severity_base": "LOW",
        "description": "Security assessment completed",
        "business_impact": "Information gathered for security analysis",
        "recommendation": "Review findings and implement appropriate security measures"
    })

def format_evidence_for_report(module_result):
    """Format module output as evidence for reports"""
    module_name = module_result.get("module_name", "")
    data = module_result.get("data", {})
    status = module_result.get("status", "")
    count = module_result.get("count", 0)
    
    if status != "SUCCESS" or not data:
        return "No detailed evidence available"
    
    # Format based on module type
    if "dns_records" in module_name:
        return format_dns_evidence(data)
    elif "open_ports" in module_name:
        return format_ports_evidence(data)
    elif "email_harvester" in module_name:
        return format_email_evidence(data)
    elif "content_discovery" in module_name:
        return format_content_evidence(data)
    elif "social_media" in module_name:
        return format_social_evidence(data)
    elif "technology_stack" in module_name:
        return format_tech_evidence(data)
    elif "subdomain" in module_name:
        return format_subdomain_evidence(data)
    elif "data_leak" in module_name:
        return format_data_leak_evidence(data)
    elif "exposed_env" in module_name:
        return format_env_evidence(data)
    else:
        return f"Found {count} items requiring review"

def format_dns_evidence(data):
    """Format DNS records as evidence"""
    evidence = []
    for record_type, records in data.items():
        if records and isinstance(records, list):
            evidence.append(f"{record_type} Records ({len(records)}):")
            for record in records[:3]:  # Show first 3
                evidence.append(f"  • {record}")
            if len(records) > 3:
                evidence.append(f"  • ... and {len(records) - 3} more")
    return "\n".join(evidence) if evidence else "DNS records enumerated"

def format_ports_evidence(data):
    """Format open ports as evidence"""
    open_ports = data.get("open_ports", [])
    if not open_ports:
        return "Port scan completed"
    
    evidence = [f"Host: {data.get('host', 'Unknown')} ({data.get('ip', 'Unknown IP')})"]
    evidence.append(f"Open Ports ({len(open_ports)}):")
    
    for port_info in open_ports[:10]:  # Show first 10
        if isinstance(port_info, dict):
            service = port_info.get('service', 'unknown')
            evidence.append(f"  • Port {port_info.get('port', '?')}: {service}")
        else:
            evidence.append(f"  • Port {port_info}")
    
    if len(open_ports) > 10:
        evidence.append(f"  • ... and {len(open_ports) - 10} more ports")
    
    return "\n".join(evidence)

def format_email_evidence(data):
    """Format found emails as evidence"""
    emails = data.get("emails", [])
    if not emails:
        return "Email harvesting completed"
    
    evidence = [f"Email Addresses Found ({len(emails)}):"]
    
    # Group by category if available
    categories = data.get("categories", {})
    if categories:
        for category, category_emails in categories.items():
            if category_emails:
                evidence.append(f"  {category.title()} ({len(category_emails)}):")
                for email in category_emails[:3]:  # Show first 3 per category
                    evidence.append(f"    • {email}")
                if len(category_emails) > 3:
                    evidence.append(f"    • ... and {len(category_emails) - 3} more")
    else:
        for email in emails[:8]:  # Show first 8
            evidence.append(f"  • {email}")
        if len(emails) > 8:
            evidence.append(f"  • ... and {len(emails) - 8} more")
    
    return "\n".join(evidence)

def format_content_evidence(data):
    """Format content discovery evidence"""
    if isinstance(data, list):
        paths = data
    else:
        paths = data.get("accessible_paths", [])
    
    if not paths:
        return "Content discovery scan completed"
    
    evidence = [f"Accessible Paths Found ({len(paths)}):"]
    
    # Group by status code if available
    status_groups = {}
    for item in paths:
        if isinstance(item, dict):
            status = item.get("status_code", "unknown")
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(item)
    
    if status_groups:
        for status_code in sorted(status_groups.keys()):
            items = status_groups[status_code]
            evidence.append(f"  Status {status_code} ({len(items)}):")
            for item in items[:3]:
                path = item.get("path", item.get("url", ""))
                evidence.append(f"    • {path}")
            if len(items) > 3:
                evidence.append(f"    • ... and {len(items) - 3} more")
    else:
        for item in paths[:5]:
            if isinstance(item, dict):
                path = item.get("path", item.get("url", str(item)))
            else:
                path = str(item)
            evidence.append(f"  • {path}")
        if len(paths) > 5:
            evidence.append(f"  • ... and {len(paths) - 5} more")
    
    return "\n".join(evidence)

def format_social_evidence(data):
    """Format social media evidence"""
    profiles = data.get("profiles", [])
    if not profiles:
        return "Social media discovery completed"
    
    evidence = [f"Social Media Profiles Found ({len(profiles)}):"]
    
    # Group by platform
    platform_groups = {}
    for profile in profiles:
        platform = profile.get("platform", "Unknown")
        if platform not in platform_groups:
            platform_groups[platform] = []
        platform_groups[platform].append(profile)
    
    for platform, platform_profiles in platform_groups.items():
        evidence.append(f"  {platform} ({len(platform_profiles)}):")
        for profile in platform_profiles[:2]:  # Show first 2 per platform
            evidence.append(f"    • {profile.get('url', 'URL not available')}")
        if len(platform_profiles) > 2:
            evidence.append(f"    • ... and {len(platform_profiles) - 2} more")
    
    return "\n".join(evidence)

def format_tech_evidence(data):
    """Format technology stack evidence"""
    if not data or not isinstance(data, dict):
        return "Technology stack analysis completed"
    
    evidence = ["Technology Stack Detected:"]
    
    for category, technologies in data.items():
        if technologies and isinstance(technologies, list):
            evidence.append(f"  {category.title()} ({len(technologies)}):")
            for tech in technologies[:3]:  # Show first 3 per category
                evidence.append(f"    • {tech}")
            if len(technologies) > 3:
                evidence.append(f"    • ... and {len(technologies) - 3} more")
    
    return "\n".join(evidence) if len(evidence) > 1 else "Technology analysis completed"

def format_subdomain_evidence(data):
    """Format subdomain evidence"""
    if isinstance(data, list):
        subdomains = data
    else:
        subdomains = data.get("brute_force", []) or data.get("subdomains", [])
    
    if not subdomains:
        return "Subdomain enumeration completed"
    
    evidence = [f"Subdomains Discovered ({len(subdomains)}):"]
    
    for subdomain in subdomains[:8]:  # Show first 8
        if isinstance(subdomain, dict):
            domain = subdomain.get("subdomain", subdomain.get("domain", ""))
            evidence.append(f"  • {domain}")
        else:
            evidence.append(f"  • {subdomain}")
    
    if len(subdomains) > 8:
        evidence.append(f"  • ... and {len(subdomains) - 8} more")
    
    return "\n".join(evidence)

def format_data_leak_evidence(data):
    """Format data leak evidence"""
    summary = data.get("summary", {})
    if not summary:
        return "Data leak check completed"
    
    evidence = ["Data Breach Analysis:"]
    
    breached = summary.get("total_compromised_emails", 0)
    domain_breaches = summary.get("total_domain_breaches", 0)
    
    if breached > 0:
        evidence.append(f"  • {breached} compromised email addresses found")
    
    if domain_breaches > 0:
        evidence.append(f"  • {domain_breaches} domain-related breaches identified")
    
    if breached == 0 and domain_breaches == 0:
        evidence.append("  • No data breaches found for target")
    
    return "\n".join(evidence)

def format_env_evidence(data):
    """Format exposed environment files evidence"""
    accessible = data.get("accessible_files", [])
    if not accessible:
        return "Environment file scan completed - no exposures found"
    
    evidence = [f"Exposed Environment Files ({len(accessible)}):"]
    
    for file_info in accessible[:5]:  # Show first 5
        filename = file_info.get("filename", "unknown")
        analysis = file_info.get("analysis", {})
        risk = analysis.get("risk_level", "UNKNOWN")
        sensitive_count = len(analysis.get("sensitive_items", []))
        
        evidence.append(f"  • {filename} (Risk: {risk})")
        if sensitive_count > 0:
            evidence.append(f"    └─ {sensitive_count} sensitive items detected")
    
    if len(accessible) > 5:
        evidence.append(f"  • ... and {len(accessible) - 5} more files")
    
    return "\n".join(evidence)

def calculate_risk_score(scan_results):
    """Calculate overall risk score from module results"""
    module_results = scan_results.get("module_results", [])
    
    if not module_results:
        return 0
    
    total_score = 0
    weight_sum = 0
    
    # Define module weights and risk factors
    module_weights = {
        "data_leak.py": 30,           # High impact
        "subdomain_takeover.py": 25,  # High impact  
        "exposed_env_files.py": 20,   # High impact
        "virustotal_scan.py": 15,     # Medium impact
        "open_ports.py": 10,          # Medium impact
        "subdomain_enum.py": 8,       # Medium impact
        "shodan.py": 8,               # Medium impact
        "content_discovery.py": 5,    # Lower impact
        "email_harvester.py": 3,      # Lower impact
        "social_media.py": 2,         # Lower impact
        "technology_stack.py": 2,     # Info only
        "dns_records.py": 1,          # Info only
        "whois_lookup.py": 1,         # Info only
    }
    
    for module_result in module_results:
        module_name = module_result.get("module_name", "")
        status = module_result.get("status", "")
        count = module_result.get("count", 0)
        severity = module_result.get("severity", "LOW")
        
        weight = module_weights.get(module_name, 1)
        weight_sum += weight
        
        if status == "SUCCESS" and count > 0:
            # Calculate module risk based on findings and severity
            severity_multiplier = {
                "CRITICAL": 4.0,
                "HIGH": 3.0, 
                "MEDIUM": 2.0,
                "LOW": 1.0
            }.get(severity, 1.0)
            
            # Risk factors: more findings = higher risk, but with diminishing returns
            finding_factor = min(count / 5, 2.0)  # Cap at 2x for many findings
            
            module_risk = weight * severity_multiplier * finding_factor
            total_score += module_risk
    
    if weight_sum == 0:
        return 0
    
    # Normalize to 0-100 scale
    max_possible_score = weight_sum * 4.0 * 2.0  # Max severity * max finding factor
    risk_score = min((total_score / max_possible_score) * 100, 100)
    
    return round(risk_score)

def determine_risk_level(risk_score):
    """Determine risk level from risk score"""
    if risk_score >= 80:
        return "critical"
    elif risk_score >= 60:
        return "high"
    elif risk_score >= 40:
        return "medium"
    elif risk_score >= 20:
        return "low"
    else:
        return "minimal"

def format_findings_for_templates(scan_results):
    """Format findings to match frontend template expectations"""
    findings = {
        "hasFindings": False,
        "totalFindings": 0,
        "riskScore": 0,
        "riskLevel": "minimal",
        "categories": {},
        "findings": [],
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
    }
    
    module_results = scan_results.get("module_results", [])
    
    for module_result in module_results:
        module_name = module_result.get("module_name", "")
        status = module_result.get("status", "")
        count = module_result.get("count", 0)
        severity = module_result.get("severity", "LOW")
        
        if status == "SUCCESS" and count > 0:
            findings["hasFindings"] = True
            findings["totalFindings"] += count
            
            # Get metadata for this module
            metadata = get_finding_metadata(module_name)
            
            # Create finding entry matching frontend format
            finding = {
                "id": f"{module_name}_{scan_results.get('scan_id', '')}",
                "title": metadata["title"],
                "category": metadata["category"],
                "severity": severity,
                "description": metadata["description"],
                "business_impact": metadata["business_impact"],
                "recommendation": metadata["recommendation"],
                "evidence": format_evidence_for_report(module_result),
                "module_name": module_name,
                "finding_count": count,
                "execution_time": module_result.get("execution_time", 0)
            }
            
            findings["findings"].append(finding)
            
            # Update category counts
            category = metadata["category"]
            findings["categories"][category] = findings["categories"].get(category, 0) + count
            
            # Update severity summary
            severity_lower = severity.lower()
            if severity_lower in findings["summary"]:
                findings["summary"][severity_lower] += count
    
    # Calculate overall risk score and level
    findings["riskScore"] = calculate_risk_score(scan_results)
    findings["riskLevel"] = determine_risk_level(findings["riskScore"])
    
    return findings

def format_scan_results_for_frontend(scan_results, target):
    """Transform scan results into frontend-expected format"""
    module_results = scan_results.get("module_results", [])
    
    # Calculate success metrics
    total_modules = len(module_results)
    successful_modules = len([r for r in module_results 
                            if r.get("status") in ["SUCCESS", "NO_DATA"]])
    
    formatted_results = {
        "scanId": scan_results.get("scan_id"),
        "target": target,
        "created_at": scan_results.get("created_at", datetime.now().isoformat()),
        "status": scan_results.get("status", "completed"),
        "total_modules": total_modules,
        "successful_modules": successful_modules,
        "execution_time": scan_results.get("total_execution_time", 0),
        
        # Risk Assessment
        "risk_score": calculate_risk_score(scan_results),
        "risk_level": determine_risk_level(calculate_risk_score(scan_results)),
        
        # Success rate for display
        "success_rate": round((successful_modules / total_modules * 100) if total_modules > 0 else 0),
        
        # Formatted findings for templates
        "formatted_findings": format_findings_for_templates(scan_results),
        
        # Raw module results for detailed analysis
        "module_results": module_results
    }
    
    return formatted_results

# =============================================================================
# ENHANCED MODULE EXECUTION WITH CLEAN OUTPUT SUPPORT
# =============================================================================

def execute_module_with_clean_output(module_script, target, scan_id):
    """Execute a module and return clean, structured output"""
    start_time = time.time()
    module_path = argus_root / "modules" / module_script
    
    result = {
        "module_name": module_script,
        "target": target,
        "scan_id": scan_id,
        "start_time": datetime.now().isoformat(),
        "status": "UNKNOWN",
        "execution_time": 0,
        "output": "",
        "error": None,
        "data": None,
        "count": 0,
        "severity": "LOW"
    }
    
    try:
        if not module_path.exists():
            result["status"] = "ERROR"
            result["error"] = f"Module file not found: {module_script}"
            return result
        
        print(f"🔍 Executing {module_script} with target: {target}")
        
        # Execute module and capture output
        timeout = get_module_timeout(module_script)
        process = subprocess.run(
            [sys.executable, str(module_path), target],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(argus_root)
        )
        
        execution_time = time.time() - start_time
        result["execution_time"] = round(execution_time, 2)
        
        # Capture raw output
        result["output"] = process.stdout
        
        if process.stderr:
            result["error"] = process.stderr
        
        # Try to parse clean output if module supports it
        if process.returncode == 0:
            clean_data = parse_module_clean_output(process.stdout, module_script)
            if clean_data:
                result.update(clean_data)
            else:
                # Fallback: parse traditional output
                result["status"] = "SUCCESS" if process.stdout.strip() else "NO_DATA"
                result["count"] = count_findings_in_output(process.stdout)
        else:
            result["status"] = "ERROR"
            
    except subprocess.TimeoutExpired:
        result["status"] = "TIMEOUT"
        result["error"] = f"Module execution timed out after {timeout}s"
        result["execution_time"] = timeout
        
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        result["execution_time"] = time.time() - start_time
    
    # Determine severity based on findings
    if result["status"] == "SUCCESS" and result["count"] > 0:
        result["severity"] = determine_module_severity(module_script, result["count"])
    
    return result

def parse_module_clean_output(output, module_script):
    """Parse clean JSON output from improved modules"""
    try:
        # Look for JSON in the output
        lines = output.strip().split('\n')
        
        # Try to find JSON content (could be mixed with console output)
        json_content = None
        
        # Look for lines that might contain JSON
        for i, line in enumerate(lines):
            if line.strip().startswith('{') and '"status"' in line:
                # Try to parse from this line to end
                remaining_lines = '\n'.join(lines[i:])
                try:
                    json_content = json.loads(remaining_lines)
                    break
                except:
                    # Try just this line
                    try:
                        json_content = json.loads(line)
                        break
                    except:
                        continue
        
        if json_content and isinstance(json_content, dict):
            # Map clean output format to our result format
            return {
                "status": json_content.get("status", "UNKNOWN"),
                "data": json_content.get("data"),
                "count": json_content.get("count", 0),
                "execution_time": json_content.get("execution_time", 0),
                "error": json_content.get("error"),
                "severity": json_content.get("severity", "LOW")
            }
    except Exception as e:
        print(f"⚠️  Could not parse clean output for {module_script}: {e}")
    
    return None

def count_findings_in_output(output):
    """Count findings in traditional module output"""
    if not output:
        return 0
    
    # Simple heuristic: count lines that look like findings
    lines = [line.strip() for line in output.split('\n') if line.strip()]
    
    # Look for common patterns
    finding_patterns = [
        '•', '*', '-', 'Found', 'Detected', 'Discovered', 
        'Open', 'Exposed', 'Vulnerable', ':', 'Record'
    ]
    
    finding_count = 0
    for line in lines:
        if any(pattern in line for pattern in finding_patterns):
            finding_count += 1
    
    return max(finding_count - 5, 0)  # Subtract headers/footers

def determine_module_severity(module_script, finding_count):
    """Determine severity based on module type and finding count"""
    high_risk_modules = [
        "data_leak.py", "subdomain_takeover.py", "exposed_env_files.py",
        "virustotal_scan.py"
    ]
    
    medium_risk_modules = [
        "open_ports.py", "subdomain_enum.py", "shodan.py", 
        "content_discovery.py"
    ]
    
    if module_script in high_risk_modules:
        if finding_count > 5:
            return "CRITICAL"
        elif finding_count > 0:
            return "HIGH"
    elif module_script in medium_risk_modules:
        if finding_count > 10:
            return "HIGH"
        elif finding_count > 0:
            return "MEDIUM"
    else:
        return "LOW"
    
    return "LOW"

# =============================================================================
# ENHANCED HTTP HANDLER WITH NEW ENDPOINTS
# =============================================================================

class ArgusHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler for Argus API with enhanced features"""
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests with enhanced endpoints"""
        try:
            if self.path == '/':
                self.send_json_response({
                    "message": "🛡️ Argus Security Assessment API - Enhanced",
                    "version": "2.1",
                    "endpoints": {
                        "health": "/api/health",
                        "modules": "/api/modules", 
                        "scans": "/api/scans",
                        "scan_details": "/api/scans/{scan_id}",
                        "report_data": "/api/scans/{scan_id}/report-data",
                        "findings": "/api/scans/{scan_id}/findings",
                        "export_clean": "/api/scans/{scan_id}/export"
                    },
                    "total_modules": 54,
                    "status": "running",
                    "findings_enabled": FINDINGS_ENABLED,
                    "features": [
                        "Clean module output parsing",
                        "Frontend template integration", 
                        "Risk scoring",
                        "Evidence formatting",
                        "Multiple export formats"
                    ]
                })
            
            elif self.path == '/api/health':
                self.handle_health()
            
            elif self.path == '/api/modules':
                self.handle_get_modules()
            
            elif self.path == '/api/scans':
                self.handle_list_scans()
            
            elif self.path.startswith('/api/scans/') and self.path.endswith('/report-data'):
                # GET /api/scans/{scan_id}/report-data
                scan_id = self.path.split('/')[-2]
                self.handle_get_report_data(scan_id)
            
            elif self.path.startswith('/api/scans/') and self.path.endswith('/findings'):
                # GET /api/scans/{scan_id}/findings
                scan_id = self.path.split('/')[-2]
                self.handle_get_findings_data(scan_id)
            
            elif self.path.startswith('/api/scans/') and self.path.endswith('/export'):
                # GET /api/scans/{scan_id}/export
                scan_id = self.path.split('/')[-2]
                self.handle_export_clean_data(scan_id)
            
            elif self.path.startswith('/api/scans/'):
                scan_id = self.path.split('/')[-1]
                self.handle_get_scan(scan_id)
            
            elif self.path == '/api/test-findings':
                self.handle_test_findings()
            
            elif self.path == '/api/findings/config':
                self.handle_findings_config()
            
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print(f"❌ GET Error: {str(e)}")
            self.send_error(500, f"Internal Server Error: {str(e)}")

    def do_POST(self):
        """Handle POST requests"""
        try:
            if self.path == '/api/scans':
                self.handle_create_scan()
            elif self.path == '/api/generate-findings':
                self.handle_generate_findings()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            print(f"❌ POST Error: {str(e)}")
            self.send_error(500, f"Internal Server Error: {str(e)}")

    def send_json_response(self, data, status_code=200):
        """Send JSON response with CORS headers"""
        response_json = json.dumps(data, indent=2, default=str)
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', str(len(response_json)))
        self.end_headers()
        self.wfile.write(response_json.encode())

    def handle_health(self):
        """Enhanced health check endpoint"""
        modules_dir = argus_root / "modules"
        modules_exist = modules_dir.exists()
        
        if modules_exist:
            module_files = list(modules_dir.glob("*.py"))
            enhanced_modules = []
            
            # Check which modules support clean output
            for module_file in module_files:
                if module_file.name in [
                    "dns_records.py", "open_ports.py", "whois_lookup.py",
                    "content_discovery.py", "email_harvester.py", "social_media.py",
                    "technology_stack.py", "data_leak.py", "exposed_env_files.py",
                    "pastebin_monitoring.py", "shodan.py", "subdomain_enum.py",
                    "subdomain_takeover.py", "virustotal_scan.py"
                ]:
                    enhanced_modules.append(module_file.name)
            
            module_count = len(module_files)
            enhanced_count = len(enhanced_modules)
        else:
            module_count = 0
            enhanced_count = 0
            enhanced_modules = []
        
        health_data = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "active_scans": len(active_scans),
            "completed_scans": len(scan_history),
            "total_modules": module_count,
            "enhanced_modules": enhanced_count,
            "enhanced_module_list": enhanced_modules,
            "modules_directory": str(modules_dir),
            "modules_exist": modules_exist,
            "findings_enabled": FINDINGS_ENABLED,
            "features": {
                "clean_output_parsing": True,
                "risk_scoring": True,
                "evidence_formatting": True,
                "template_integration": True
            }
        }
        
        self.send_json_response(health_data)

    def handle_get_modules(self):
        """Get available modules with enhanced metadata - FIXED VERSION"""
        
        # Enhanced modules that support the new findings system (define at function level)
        enhanced_modules = [
            "dns_records.py", "open_ports.py", "whois_lookup.py",
            "content_discovery.py", "email_harvester.py", "social_media.py", 
            "technology_stack.py", "data_leak.py", "exposed_env_files.py",
            "pastebin_monitoring.py", "shodan.py", "subdomain_enum.py",
            "subdomain_takeover.py", "virustotal_scan.py"
        ]
        
        # Import the full module list from argus.py
        try:
            # Add the argus root to path if not already there
            import sys
            from pathlib import Path
            argus_root = Path(__file__).parent.parent.parent
            if str(argus_root) not in sys.path:
                sys.path.insert(0, str(argus_root))
            
            from argus import tools
            original_modules_available = True
            print(f"✅ Loaded {len(tools)} modules from argus.py")
        except ImportError as e:
            print(f"⚠️  Could not import from argus.py: {e}")
            original_modules_available = False
            tools = []
        
        modules_data = []
        
        if original_modules_available and tools:
            # Use the full 54-module list from argus.py
            for tool in tools:
                # Skip the special "Run All" and "BEAST MODE" entries
                if not tool['script'] or tool['section'] in ['Run All Scripts', 'Special Mode']:
                    continue
                    
                module_script = tool['script']
                is_enhanced = module_script in enhanced_modules
                
                # Get enhanced metadata if available, otherwise use basic info
                if is_enhanced:
                    try:
                        metadata = get_finding_metadata(module_script)
                        # OVERRIDE: Force enhanced modules into the 3 main categories
                        section_to_category = {
                            'Network & Infrastructure': 'Network and Infrastructure',
                            'Web Application Analysis': 'Web Application', 
                            'Security & Threat Intelligence': 'Security & Threat Intelligence'
                        }
                        # Use the tool's original section, not the metadata category
                        category = section_to_category.get(tool['section'], 'Network and Infrastructure')
                        description = metadata["description"]
                        severity_base = metadata["severity_base"]
                    except:
                        # Fallback if metadata function fails - use 3 main categories
                        section_to_category = {
                            'Network & Infrastructure': 'Network and Infrastructure',
                            'Web Application Analysis': 'Web Application', 
                            'Security & Threat Intelligence': 'Security & Threat Intelligence'
                        }
                        category = section_to_category.get(tool['section'], 'Network and Infrastructure')
                        description = f"{tool['name']} - Enhanced reconnaissance module"
                        severity_base = "medium"
                else:
                    # Map ALL modules to the 3 main categories only
                    section_to_category = {
                        'Network & Infrastructure': 'Network and Infrastructure',
                        'Web Application Analysis': 'Web Application', 
                        'Security & Threat Intelligence': 'Security & Threat Intelligence'
                    }
                    # Force everything into one of the 3 categories
                    category = section_to_category.get(tool['section'], 'Network and Infrastructure')
                    description = f"{tool['name']} - {tool['section']} tool"
                    severity_base = "medium"
                
                module_info = {
                    "id": int(tool['number']) if tool['number'].isdigit() else len(modules_data) + 1,
                    "name": tool['name'],
                    "script": module_script,
                    "category": category,
                    "description": description,
                    "severity_base": severity_base,
                    "enhanced": is_enhanced,
                    "supports_clean_output": is_enhanced,
                    "estimated_time": MODULE_TIMEOUTS.get(module_script, 60),
                    "section": tool['section'],  # Keep original section info
                    "number": tool['number']     # Keep original numbering
                }
                modules_data.append(module_info)
                
        else:
            # Fallback to enhanced modules only if argus.py import fails
            print("⚠️  Using fallback enhanced modules only")
            for i, module_script in enumerate(enhanced_modules, 1):
                try:
                    metadata = get_finding_metadata(module_script)
                    module_info = {
                        "id": i,
                        "name": metadata["title"],
                        "script": module_script,
                        "category": metadata["category"],
                        "description": metadata["description"],
                        "severity_base": metadata["severity_base"],
                        "enhanced": True,
                        "supports_clean_output": True,
                        "estimated_time": MODULE_TIMEOUTS.get(module_script, 60)
                    }
                    modules_data.append(module_info)
                except Exception as e:
                    print(f"⚠️  Error loading metadata for {module_script}: {e}")
        
        # Sort modules by category and then by name for consistent ordering
        modules_data.sort(key=lambda x: (x['category'], x['name']))
        
        # Generate summary statistics
        total_modules = len(modules_data)
        enhanced_count = len([m for m in modules_data if m.get('enhanced', False)])
        categories = list(set(m['category'] for m in modules_data))
        
        response_data = {
            "modules": modules_data,
            "total": total_modules,
            "enhanced_count": enhanced_count,
            "legacy_count": total_modules - enhanced_count,
            "categories": sorted(categories),
            "status": "success",
            "source": "argus.py" if original_modules_available else "enhanced_only",
            "features": {
                "enhanced_findings": enhanced_count > 0,
                "legacy_support": total_modules > enhanced_count,
                "full_module_set": original_modules_available
            }
        }
        
        print(f"📊 Returning {total_modules} modules ({enhanced_count} enhanced, {total_modules - enhanced_count} legacy)")
        self.send_json_response(response_data)
    
    def handle_create_scan(self):
        """Enhanced scan creation with clean output support"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            target = data.get('target')
            modules = data.get('modules', [])
            
            if not target:
                self.send_json_response({'error': 'Target is required'}, 400)
                return
            
            if not modules:
                self.send_json_response({'error': 'At least one module must be selected'}, 400)
                return
            
            # Create scan record
            scan_id = str(uuid.uuid4())
            scan_record = {
                "scan_id": scan_id,
                "target": target,
                "modules": modules,
                "status": "running",
                "created_at": datetime.now().isoformat(),
                "module_results": [],
                "total_execution_time": 0,
                "enhanced_output": True
            }
            
            def execute_scan(scan_id):
                """Execute scan with enhanced module support"""
                start_time = time.time()
                scan_record["module_results"] = []
                
                try:
                    for module_script in modules:
                        if scan_record["status"] == "cancelled":
                            break
                        
                        print(f"🔍 Running enhanced module: {module_script}")
                        module_result = execute_module_with_clean_output(module_script, target, scan_id)
                        scan_record["module_results"].append(module_result)
                        
                        print(f"✅ {module_script}: {module_result['status']} "
                              f"({module_result['count']} findings, {module_result['execution_time']}s)")
                    
                    scan_record["total_execution_time"] = time.time() - start_time
                    scan_record["status"] = "completed"
                    scan_record["completed_at"] = datetime.now().isoformat()
                    
                    # Move to history
                    scan_history[scan_id] = scan_record.copy()
                    if scan_id in active_scans:
                        del active_scans[scan_id]
                    
                    print(f"✅ Scan {scan_id} completed in {scan_record['total_execution_time']:.2f}s")
                    
                except Exception as e:
                    scan_record["status"] = "error"
                    scan_record["error"] = str(e)
                    scan_record["total_execution_time"] = time.time() - start_time
                    print(f"❌ Scan {scan_id} failed: {str(e)}")
            
            # Start scan in background
            active_scans[scan_id] = scan_record
            scan_thread = threading.Thread(target=execute_scan, args=(scan_id,))
            scan_thread.daemon = True
            scan_thread.start()
            
            print(f"✅ Created enhanced scan {scan_id} for {target} with {len(modules)} modules")
            
            self.send_json_response({
                "scan_id": scan_id,
                "status": "created",
                "message": "Enhanced scan created successfully",
                "target": target,
                "modules": modules,
                "enhanced_features": True,
                "findings_enabled": FINDINGS_ENABLED
            }, 201)
            
        except Exception as e:
            print(f"❌ Error creating scan: {str(e)}")
            self.send_json_response({'error': str(e)}, 500)

    def handle_get_scan(self, scan_id):
        """Get scan status with enhanced information"""
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
        elif scan_id in scan_history:
            scan_data = scan_history[scan_id]
        else:
            self.send_json_response({"error": "Scan not found"}, 404)
            return
        
        # Add enhanced metadata
        enhanced_data = scan_data.copy()
        enhanced_data["enhanced_output"] = True
        enhanced_data["total_findings"] = sum(r.get("count", 0) for r in scan_data.get("module_results", []))
        enhanced_data["successful_modules"] = len([r for r in scan_data.get("module_results", []) 
                                                 if r.get("status") in ["SUCCESS", "NO_DATA"]])
        
        self.send_json_response(enhanced_data)

    def handle_get_report_data(self, scan_id):
        """NEW: Get scan data formatted for frontend templates"""
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
        elif scan_id in scan_history:
            scan_data = scan_history[scan_id]
        else:
            self.send_json_response({"error": "Scan not found"}, 404)
            return
        
        try:
            # Format for frontend templates
            formatted_data = format_scan_results_for_frontend(scan_data, scan_data.get("target", ""))
            
            self.send_json_response({
                "success": True,
                "data": formatted_data,
                "scan_id": scan_id,
                "generated_at": datetime.now().isoformat()
            })
            
        except Exception as e:
            print(f"❌ Error formatting report data: {str(e)}")
            self.send_json_response({"error": f"Failed to format report data: {str(e)}"}, 500)

    def handle_get_findings_data(self, scan_id):
        """NEW: Get findings data in format expected by frontend templates"""
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
        elif scan_id in scan_history:
            scan_data = scan_history[scan_id]
        else:
            self.send_json_response({"error": "Scan not found"}, 404)
            return
        
        try:
            # Generate findings in format expected by templates
            findings_data = format_findings_for_templates(scan_data)
            
            self.send_json_response({
                "success": True,
                "data": findings_data,
                "scan_id": scan_id,
                "generated_at": datetime.now().isoformat()
            })
            
        except Exception as e:
            print(f"❌ Error generating findings data: {str(e)}")
            self.send_json_response({"error": f"Failed to generate findings: {str(e)}"}, 500)

    def handle_export_clean_data(self, scan_id):
        """NEW: Export clean, structured scan data"""
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
        elif scan_id in scan_history:
            scan_data = scan_history[scan_id]
        else:
            self.send_json_response({"error": "Scan not found"}, 404)
            return
        
        try:
            # Prepare clean export data
            export_data = {
                "metadata": {
                    "scan_id": scan_id,
                    "target": scan_data.get("target"),
                    "created_at": scan_data.get("created_at"),
                    "completed_at": scan_data.get("completed_at"),
                    "status": scan_data.get("status"),
                    "total_execution_time": scan_data.get("total_execution_time", 0),
                    "export_generated_at": datetime.now().isoformat(),
                    "export_version": "2.1"
                },
                "summary": {
                    "total_modules": len(scan_data.get("module_results", [])),
                    "successful_modules": len([r for r in scan_data.get("module_results", []) 
                                             if r.get("status") in ["SUCCESS", "NO_DATA"]]),
                    "total_findings": sum(r.get("count", 0) for r in scan_data.get("module_results", [])),
                    "risk_score": calculate_risk_score(scan_data),
                    "risk_level": determine_risk_level(calculate_risk_score(scan_data))
                },
                "module_results": [],
                "findings": format_findings_for_templates(scan_data),
                "formatted_for_reports": format_scan_results_for_frontend(scan_data, scan_data.get("target", ""))
            }
            
            # Clean module results for export
            for module_result in scan_data.get("module_results", []):
                clean_result = {
                    "module_name": module_result.get("module_name"),
                    "status": module_result.get("status"),
                    "execution_time": module_result.get("execution_time", 0),
                    "findings_count": module_result.get("count", 0),
                    "severity": module_result.get("severity", "LOW"),
                    "data": module_result.get("data"),
                    "evidence": format_evidence_for_report(module_result),
                    "metadata": get_finding_metadata(module_result.get("module_name", "")),
                    "error": module_result.get("error") if module_result.get("status") in ["ERROR", "TIMEOUT"] else None
                }
                export_data["module_results"].append(clean_result)
            
            self.send_json_response({
                "success": True,
                "export_data": export_data,
                "download_info": {
                    "filename": f"argus_scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    "format": "json",
                    "size_kb": round(len(json.dumps(export_data)) / 1024, 2)
                }
            })
            
        except Exception as e:
            print(f"❌ Error exporting clean data: {str(e)}")
            self.send_json_response({"error": f"Failed to export data: {str(e)}"}, 500)

    def handle_list_scans(self):
        """List all scans with enhanced information"""
        all_scans = []
        
        # Add active scans
        for scan_id, scan_data in active_scans.items():
            enhanced_scan = scan_data.copy()
            enhanced_scan["is_active"] = True
            enhanced_scan["total_findings"] = sum(r.get("count", 0) for r in scan_data.get("module_results", []))
            all_scans.append(enhanced_scan)
        
        # Add completed scans
        for scan_id, scan_data in scan_history.items():
            enhanced_scan = scan_data.copy() 
            enhanced_scan["is_active"] = False
            enhanced_scan["total_findings"] = sum(r.get("count", 0) for r in scan_data.get("module_results", []))
            all_scans.append(enhanced_scan)
        
        # Sort by creation time (newest first)
        all_scans.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        response_data = {
            "scans": all_scans[:50],  # Limit to 50 most recent
            "total": len(all_scans),
            "active": len(active_scans),
            "completed": len(scan_history),
            "enhanced_features": True,
            "findings_enabled": FINDINGS_ENABLED
        }
        
        self.send_json_response(response_data)

    def handle_generate_findings(self):
        """Generate security findings from module results (legacy endpoint)"""
        if not FINDINGS_ENABLED:
            self.send_json_response({"error": "Findings system not available"}, 503)
            return
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode())
            
            if not data or 'module_results' not in data:
                self.send_json_response({'error': 'module_results required'}, 400)
                return
            
            module_results = data['module_results']
            target = data.get('target', 'Unknown')
            
            # Use enhanced findings generation
            findings_data = format_findings_for_templates({"module_results": module_results})
            
            self.send_json_response({
                'success': True,
                'data': findings_data,
                'enhanced': True
            })
            
        except Exception as e:
            print(f"❌ Error generating findings: {str(e)}")
            self.send_json_response({'error': str(e)}, 500)

    def handle_test_findings(self):
        """Test endpoint for enhanced findings system"""
        if not FINDINGS_ENABLED:
            self.send_json_response({"error": "Findings system not available"}, 503)
            return
        
        try:
            # Sample enhanced module results
            test_module_results = [
                {
                    'module_name': 'dns_records.py',
                    'status': 'SUCCESS',
                    'execution_time': 2.34,
                    'count': 12,
                    'severity': 'LOW',
                    'data': {
                        'A': ['142.250.190.14'],
                        'MX': ['10 smtp.google.com.'],
                        'NS': ['ns1.google.com.', 'ns2.google.com.']
                    }
                },
                {
                    'module_name': 'open_ports.py',
                    'status': 'SUCCESS', 
                    'execution_time': 15.67,
                    'count': 3,
                    'severity': 'MEDIUM',
                    'data': {
                        'host': 'example.com',
                        'ip': '93.184.216.34',
                        'open_ports': [
                            {'port': 80, 'service': 'http'},
                            {'port': 443, 'service': 'https'}
                        ]
                    }
                },
                {
                    'module_name': 'data_leak.py',
                    'status': 'SUCCESS',
                    'execution_time': 45.2, 
                    'count': 2,
                    'severity': 'HIGH',
                    'data': {
                        'summary': {
                            'total_compromised_emails': 2,
                            'total_domain_breaches': 1
                        }
                    }
                }
            ]
            
            # Test enhanced findings generation
            scan_data = {"module_results": test_module_results}
            findings_data = format_findings_for_templates(scan_data)
            report_data = format_scan_results_for_frontend(scan_data, 'example.com')
            
            self.send_json_response({
                'success': True,
                'message': 'Enhanced findings system is working correctly',
                'test_data': {
                    'findings': findings_data,
                    'report_data': report_data,
                    'risk_score': calculate_risk_score(scan_data),
                    'sample_evidence': format_evidence_for_report(test_module_results[1])
                }
            })
            
        except Exception as e:
            print(f"❌ Error testing enhanced findings: {str(e)}")
            self.send_json_response({'error': str(e)}, 500)

    def handle_findings_config(self):
        """Get enhanced findings system configuration"""
        if not FINDINGS_ENABLED:
            self.send_json_response({"error": "Findings system not available"}, 503)
            return
        
        try:
            enhanced_modules = [
                "dns_records.py", "open_ports.py", "whois_lookup.py",
                "content_discovery.py", "email_harvester.py", "social_media.py",
                "technology_stack.py", "data_leak.py", "exposed_env_files.py", 
                "pastebin_monitoring.py", "shodan.py", "subdomain_enum.py",
                "subdomain_takeover.py", "virustotal_scan.py"
            ]
            
            categories = set()
            for module in enhanced_modules:
                metadata = get_finding_metadata(module)
                categories.add(metadata["category"])
            
            self.send_json_response({
                'success': True,
                'data': {
                    'enhanced_modules_count': len(enhanced_modules),
                    'enhanced_modules': enhanced_modules,
                    'categories': list(categories),
                    'features': [
                        'Clean output parsing',
                        'Risk scoring', 
                        'Evidence formatting',
                        'Template integration',
                        'Multiple export formats'
                    ],
                    'risk_calculation': {
                        'weights': {
                            'data_leak.py': 30,
                            'subdomain_takeover.py': 25,
                            'exposed_env_files.py': 20,
                            'virustotal_scan.py': 15,
                            'other_modules': '1-10'
                        },
                        'severity_multipliers': {
                            'CRITICAL': 4.0,
                            'HIGH': 3.0,
                            'MEDIUM': 2.0, 
                            'LOW': 1.0
                        }
                    }
                }
            })
            
        except Exception as e:
            print(f"❌ Error getting enhanced config: {str(e)}")
            self.send_json_response({'error': str(e)}, 500)

# =============================================================================
# MAIN SERVER STARTUP
# =============================================================================

def start_server():
    """Start the enhanced Argus server"""
    try:
        with socketserver.TCPServer((HOST, PORT), ArgusHTTPHandler) as httpd:
            print("=" * 60)
            print("🛡️  ARGUS ENHANCED SECURITY ASSESSMENT SERVER")
            print("=" * 60)
            print(f"🚀 Server running at http://{HOST}:{PORT}")
            print(f"📁 Modules directory: {argus_root / 'modules'}")
            print(f"🔧 Enhanced features: ENABLED")
            print(f"📊 Findings system: {'ENABLED' if FINDINGS_ENABLED else 'DISABLED'}")
            print(f"🎯 Enhanced modules: 14/54")
            print("=" * 60)
            print("📡 Available endpoints:")
            print("   GET  /                          - API information")
            print("   GET  /api/health                - Health check")
            print("   GET  /api/modules               - List enhanced modules")
            print("   POST /api/scans                 - Create new scan")
            print("   GET  /api/scans                 - List all scans")
            print("   GET  /api/scans/{id}            - Get scan details")
            print("   GET  /api/scans/{id}/report-data - Get template-ready data")
            print("   GET  /api/scans/{id}/findings   - Get findings for reports")
            print("   GET  /api/scans/{id}/export     - Export clean data")
            print("=" * 60)
            print("🔥 NEW FEATURES:")
            print("   ✅ Clean module output parsing")
            print("   ✅ Frontend template integration")
            print("   ✅ Automated risk scoring")
            print("   ✅ Evidence formatting")
            print("   ✅ Professional PDF reports")
            print("=" * 60)
            print("🎬 Ready for requests! Press Ctrl+C to stop")
            print()
            
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {str(e)}")

if __name__ == "__main__":
    start_server()