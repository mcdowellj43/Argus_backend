#!/usr/bin/env python3
"""
Service Banner Vulnerability Scanner Module
Analyzes service banners and version information to identify known vulnerabilities 
in specific software versions running on target systems.
"""

import os
import sys
import socket
import requests
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Fix encoding issues for Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.util import clean_domain_input
    from config.settings import USER_AGENT, DEFAULT_TIMEOUT
except ImportError:
    # Fallback implementations
    def clean_domain_input(domain):
        """Clean domain input"""
        if not domain:
            return ""
        domain = domain.strip().lower()
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.replace('www.', '')
        if '/' in domain:
            domain = domain.split('/')[0]
        return domain
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    DEFAULT_TIMEOUT = 10

# Import findings system
try:
    from config.findings_rules import evaluate_findings, display_findings_result
    FINDINGS_AVAILABLE = True
except ImportError:
    print("[W] Findings system not available - running in legacy mode")
    FINDINGS_AVAILABLE = False

def get_vulnerable_versions_database():
    """Get database of known vulnerable software versions"""
    return {
        "SSH": {
            "OpenSSH": {
                "vulnerable_versions": [
                    {"version": "7.1", "cve": "CVE-2016-6210", "description": "User enumeration vulnerability"},
                    {"version": "6.9", "cve": "CVE-2015-5600", "description": "Privilege escalation vulnerability"},
                    {"version": "5.4", "cve": "CVE-2010-5107", "description": "Memory corruption vulnerability"}
                ]
            }
        },
        "HTTP": {
            "Apache": {
                "vulnerable_versions": [
                    {"version": "2.4.49", "cve": "CVE-2021-41773", "description": "Path traversal vulnerability"},
                    {"version": "2.4.50", "cve": "CVE-2021-42013", "description": "Path traversal vulnerability"},
                    {"version": "2.4.51", "cve": "CVE-2021-41773", "description": "Path traversal vulnerability"}
                ]
            },
            "nginx": {
                "vulnerable_versions": [
                    {"version": "1.20.0", "cve": "CVE-2021-23017", "description": "DNS resolver vulnerability"},
                    {"version": "1.19.0", "cve": "CVE-2020-12440", "description": "Memory corruption vulnerability"}
                ]
            },
            "IIS": {
                "vulnerable_versions": [
                    {"version": "10.0", "cve": "CVE-2021-31166", "description": "HTTP protocol stack vulnerability"},
                    {"version": "8.5", "cve": "CVE-2015-1635", "description": "HTTP.sys vulnerability"}
                ]
            }
        },
        "FTP": {
            "vsftpd": {
                "vulnerable_versions": [
                    {"version": "2.3.4", "cve": "CVE-2011-2523", "description": "Backdoor vulnerability"},
                    {"version": "2.3.2", "cve": "CVE-2011-0762", "description": "Denial of service vulnerability"}
                ]
            },
            "ProFTPD": {
                "vulnerable_versions": [
                    {"version": "1.3.3c", "cve": "CVE-2011-4130", "description": "Remote code execution vulnerability"}
                ]
            }
        },
        "SMTP": {
            "Postfix": {
                "vulnerable_versions": [
                    {"version": "2.11.0", "cve": "CVE-2014-7169", "description": "Shellshock vulnerability"}
                ]
            },
            "Exim": {
                "vulnerable_versions": [
                    {"version": "4.92", "cve": "CVE-2019-10149", "description": "Remote code execution vulnerability"}
                ]
            }
        },
        "MySQL": {
            "MySQL": {
                "vulnerable_versions": [
                    {"version": "5.7.0", "cve": "CVE-2016-6662", "description": "Privilege escalation vulnerability"},
                    {"version": "5.6.0", "cve": "CVE-2016-6663", "description": "Remote code execution vulnerability"}
                ]
            }
        },
        "PostgreSQL": {
            "PostgreSQL": {
                "vulnerable_versions": [
                    {"version": "9.6.0", "cve": "CVE-2019-9193", "description": "Remote code execution vulnerability"}
                ]
            }
        }
    }

def grab_service_banner(target, port, service_type):
    """Grab service banner for version detection"""
    banner = ""
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        if service_type == "HTTP":
            # Send HTTP request
            request = "HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n".format(target, USER_AGENT)
            sock.send(request.encode())
        elif service_type == "FTP":
            # Send FTP command
            sock.send(b"HELP\r\n")
        elif service_type == "SMTP":
            # Send SMTP command
            sock.send(b"HELP\r\n")
        elif service_type == "SSH":
            # SSH sends banner automatically
            pass
        else:
            # Generic probe
            sock.send(b"\r\n")
        
        # Receive response
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
    except Exception as e:
        print(f"[E] Error grabbing banner from {target}:{port} - {str(e)}")
    
    return banner

def extract_version_from_banner(banner, service_type):
    """Extract version information from service banner"""
    version_patterns = {
        "SSH": [
            r"SSH-(\d+\.\d+)",
            r"OpenSSH_(\d+\.\d+)",
            r"SSH-2\.0-OpenSSH_(\d+\.\d+)"
        ],
        "HTTP": [
            r"Server:\s*([^\r\n]+)",
            r"Apache/(\d+\.\d+\.\d+)",
            r"nginx/(\d+\.\d+\.\d+)",
            r"Microsoft-IIS/(\d+\.\d+)"
        ],
        "FTP": [
            r"vsFTPd\s+(\d+\.\d+\.\d+)",
            r"ProFTPD\s+(\d+\.\d+\.\d+)",
            r"FileZilla\s+Server\s+(\d+\.\d+\.\d+)"
        ],
        "SMTP": [
            r"Postfix\s+(\d+\.\d+\.\d+)",
            r"Exim\s+(\d+\.\d+\.\d+)",
            r"Sendmail\s+(\d+\.\d+\.\d+)"
        ],
        "MySQL": [
            r"mysql.*?(\d+\.\d+\.\d+)",
            r"MySQL.*?(\d+\.\d+\.\d+)"
        ],
        "PostgreSQL": [
            r"PostgreSQL.*?(\d+\.\d+\.\d+)"
        ],
        "Redis": [
            r"redis.*?(\d+\.\d+\.\d+)"
        ],
        "MongoDB": [
            r"MongoDB.*?(\d+\.\d+\.\d+)"
        ]
    }
    
    patterns = version_patterns.get(service_type, [])
    
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None

def identify_service_software(banner, service_type):
    """Identify the specific software from banner"""
    software_patterns = {
        "HTTP": {
            "Apache": r"Apache",
            "nginx": r"nginx",
            "IIS": r"Microsoft-IIS",
            "lighttpd": r"lighttpd",
            "OpenResty": r"OpenResty"
        },
        "FTP": {
            "vsftpd": r"vsFTPd",
            "ProFTPD": r"ProFTPD",
            "FileZilla": r"FileZilla",
            "Pure-FTPd": r"Pure-FTPd"
        },
        "SMTP": {
            "Postfix": r"Postfix",
            "Exim": r"Exim",
            "Sendmail": r"Sendmail",
            "Exchange": r"Microsoft ESMTP"
        },
        "SSH": {
            "OpenSSH": r"OpenSSH",
            "Dropbear": r"dropbear",
            "SSH2": r"SSH-2"
        }
    }
    
    patterns = software_patterns.get(service_type, {})
    
    for software, pattern in patterns.items():
        if re.search(pattern, banner, re.IGNORECASE):
            return software
    
    return "Unknown"

def check_version_vulnerabilities(service_type, software, version):
    """Check if version has known vulnerabilities"""
    vulnerabilities = []
    
    vuln_db = get_vulnerable_versions_database()
    service_vulns = vuln_db.get(service_type, {})
    software_vulns = service_vulns.get(software, {})
    
    if not software_vulns:
        return vulnerabilities
    
    vulnerable_versions = software_vulns.get("vulnerable_versions", [])
    
    for vuln_info in vulnerable_versions:
        vuln_version = vuln_info.get("version")
        if version and vuln_version:
            # Simple version comparison (can be enhanced)
            if version.startswith(vuln_version):
                vulnerabilities.append({
                    "type": "Known Vulnerability",
                    "severity": "high",
                    "description": f"Known vulnerability in {software} {version}: {vuln_info.get('description')}",
                    "cve": vuln_info.get("cve"),
                    "software": software,
                    "version": version,
                    "service": service_type
                })
    
    return vulnerabilities

def scan_service_banners(target, ports_and_services):
    """Scan multiple services for banner vulnerabilities"""
    results = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_service = {}
        
        for port, service_type in ports_and_services:
            future = executor.submit(scan_single_service_banner, target, port, service_type)
            future_to_service[future] = (port, service_type)
        
        for future in as_completed(future_to_service):
            port, service_type = future_to_service[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"[E] Error scanning {target}:{port} - {str(e)}")
    
    return results

def scan_single_service_banner(target, port, service_type):
    """Scan a single service for banner vulnerabilities"""
    try:
        # Grab service banner
        banner = grab_service_banner(target, port, service_type)
        
        if not banner:
            return None
        
        # Extract version information
        version = extract_version_from_banner(banner, service_type)
        software = identify_service_software(banner, service_type)
        
        # Check for vulnerabilities
        vulnerabilities = check_version_vulnerabilities(service_type, software, version)
        
        # Additional security checks
        security_issues = []
        
        # Check for information disclosure
        if "Server" in banner and service_type == "HTTP":
            security_issues.append({
                "type": "Information Disclosure",
                "severity": "medium",
                "description": "Server version information disclosed in HTTP headers",
                "service": service_type
            })
        
        # Check for default configurations
        if "default" in banner.lower() or "welcome" in banner.lower():
            security_issues.append({
                "type": "Default Configuration",
                "severity": "medium",
                "description": "Service appears to be running with default configuration",
                "service": service_type
            })
        
        return {
            "port": port,
            "service": service_type,
            "software": software,
            "version": version,
            "banner": banner[:200] + "..." if len(banner) > 200 else banner,
            "vulnerabilities": vulnerabilities,
            "security_issues": security_issues
        }
    
    except Exception as e:
        print(f"[E] Error scanning service banner for {target}:{port} - {str(e)}")
        return None

def get_common_service_ports():
    """Get list of common service ports to scan"""
    return [
        (21, "FTP"),
        (22, "SSH"),
        (23, "Telnet"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (443, "HTTP"),
        (445, "SMB"),
        (1433, "MSSQL"),
        (1521, "Oracle"),
        (3306, "MySQL"),
        (3389, "RDP"),
        (5432, "PostgreSQL"),
        (5900, "VNC"),
        (6379, "Redis"),
        (8080, "HTTP"),
        (8443, "HTTP"),
        (27017, "MongoDB")
    ]

def perform_service_banner_scan(target):
    """Perform comprehensive service banner vulnerability scan"""
    print(f"[I] Starting service banner vulnerability scan for {target}")
    
    # Get common ports to scan
    ports_and_services = get_common_service_ports()
    
    # Scan service banners
    results = scan_service_banners(target, ports_and_services)
    
    # Aggregate results
    total_vulnerabilities = sum(len(r.get("vulnerabilities", [])) for r in results)
    total_security_issues = sum(len(r.get("security_issues", [])) for r in results)
    
    return {
        "target": target,
        "services_scanned": len(results),
        "services_with_vulnerabilities": len([r for r in results if r.get("vulnerabilities")]),
        "total_vulnerabilities": total_vulnerabilities,
        "total_security_issues": total_security_issues,
        "service_details": results,
        "scan_time": datetime.now().isoformat()
    }

def assess_service_banner_vulnerability_risk(results):
    """Assess security risk level of service banner vulnerability findings"""
    findings = []
    severity = "I"
    
    service_details = results.get("service_details", [])
    total_vulnerabilities = results.get("total_vulnerabilities", 0)
    total_security_issues = results.get("total_security_issues", 0)
    
    if not service_details:
        return findings, severity
    
    # Count vulnerabilities by severity
    critical_vulns = []
    high_vulns = []
    medium_vulns = []
    
    for service in service_details:
        for vuln in service.get("vulnerabilities", []):
            if vuln.get("severity") == "critical":
                critical_vulns.append(vuln)
            elif vuln.get("severity") == "high":
                high_vulns.append(vuln)
            elif vuln.get("severity") == "medium":
                medium_vulns.append(vuln)
    
    # Critical findings
    if critical_vulns:
        severity = "C"
        findings.append(f"Critical vulnerabilities found: {len(critical_vulns)} critical issues detected")
        
        # List critical vulnerabilities
        for vuln in critical_vulns[:3]:  # Show first 3
            software = vuln.get("software", "Unknown")
            version = vuln.get("version", "Unknown")
            findings.append(f"Critical: {software} {version} - {vuln.get('description', 'No description')}")
    
    # High findings
    if high_vulns:
        if severity == "I":
            severity = "H"
        findings.append(f"High-risk vulnerabilities: {len(high_vulns)} high-severity issues detected")
    
    # Medium findings
    if medium_vulns:
        if severity == "I":
            severity = "W"
        findings.append(f"Medium-risk vulnerabilities: {len(medium_vulns)} medium-severity issues detected")
    
    # Security issues
    if total_security_issues > 0:
        if severity == "I":
            severity = "W"
        findings.append(f"Security issues detected: {total_security_issues} configuration and information disclosure issues")
    
    # Service enumeration
    if service_details:
        if severity == "I":
            severity = "W"
        findings.append(f"Services identified: {len(service_details)} services with version information")
        
        # Identify high-risk services
        high_risk_services = ['SSH', 'FTP', 'SMTP', 'MySQL', 'PostgreSQL']
        risky_services = [s for s in service_details if s.get("service") in high_risk_services]
        
        if risky_services:
            findings.append(f"High-risk services: {len(risky_services)} potentially vulnerable services identified")
    
    return findings, severity

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] Service Banner Vulnerability Scanner - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("[E] FAILED: Empty target provided")
            return {
                "status": "FAILED",
                "error": "Empty target",
                "execution_time": (datetime.now() - start_time).total_seconds()
            }
        
        # Clean target input
        target = clean_domain_input(target)
        if not target:
            print("[E] FAILED: Invalid target format")
            return {
                "status": "FAILED",
                "error": "Invalid target format",
                "execution_time": (datetime.now() - start_time).total_seconds()
            }
        
        print(f"[I] Target: {target}")
        print()
        
        # Perform service banner vulnerability scan
        results = perform_service_banner_scan(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Prepare scan data for findings evaluation
        service_details = results.get("service_details", [])
        total_vulnerabilities = results.get("total_vulnerabilities", 0)
        total_security_issues = results.get("total_security_issues", 0)
        
        scan_data = {
            "target": target,
            "services_scanned": len(service_details),
            "services_with_vulnerabilities": len([s for s in service_details if s.get("vulnerabilities")]),
            "total_vulnerabilities": total_vulnerabilities,
            "total_security_issues": total_security_issues,
            "service_details": service_details,
            "status": "SUCCESS" if service_details else "NO_DATA",
            "scan_completed": True
        }
        
        if service_details:
            # Assess security risk
            security_findings, severity = assess_service_banner_vulnerability_risk(results)
            
            print(f"[{severity}] VULNERABILITIES FOUND: {total_vulnerabilities} vulnerabilities detected across {len(service_details)} services")
            
            # Display vulnerability summary
            if total_vulnerabilities > 0:
                print(f"[{severity}] Vulnerability Summary:")
                critical_count = len([v for s in service_details for v in s.get("vulnerabilities", []) if v.get("severity") == "critical"])
                high_count = len([v for s in service_details for v in s.get("vulnerabilities", []) if v.get("severity") == "high"])
                medium_count = len([v for s in service_details for v in s.get("vulnerabilities", []) if v.get("severity") == "medium"])
                
                if critical_count > 0:
                    print(f"  [C] Critical: {critical_count}")
                if high_count > 0:
                    print(f"  [H] High: {high_count}")
                if medium_count > 0:
                    print(f"  [M] Medium: {medium_count}")
                print()
            
            # Display service details
            if service_details:
                print(f"[I] SERVICE DETAILS ({len(service_details)}):")
                for service in service_details[:10]:  # Show first 10
                    port = service.get("port")
                    service_type = service.get("service")
                    software = service.get("software", "Unknown")
                    version = service.get("version", "Unknown")
                    vuln_count = len(service.get("vulnerabilities", []))
                    
                    print(f"  [I] {port}/tcp - {service_type} ({software} {version}) - {vuln_count} vulnerabilities")
                
                if len(service_details) > 10:
                    print(f"  [I] ... and {len(service_details) - 10} more services")
                print()
            
            # Display security findings
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
        else:
            print("[I] NO DATA: No services or vulnerabilities found")
            security_findings = []
            severity = "I"
        
        print()
        
        # Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("service_banner_vulns.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            if service_details:
                findings = security_findings if security_findings else [f"Found {total_vulnerabilities} vulnerabilities"]
            else:
                findings = ["No service banner vulnerabilities detected"]
            
            findings_result = {
                "success": total_vulnerabilities > 0,
                "severity": severity,
                "findings": findings,
                "has_findings": total_vulnerabilities > 0,
                "category": "Service Banner Vulnerability Analysis"
            }
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        print()
        
        # Return standardized format
        return {
            "status": "SUCCESS" if findings_result["success"] else "FAILED",
            "data": scan_data,
            "findings": findings_result,
            "execution_time": execution_time,
            "target": target,
            # Keep legacy fields for backward compatibility
            "service_details": service_details,
            "total_vulnerabilities": total_vulnerabilities,
            "severity": findings_result["severity"]
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Service banner vulnerability scan stopped by user")
        return {
            "status": "INTERRUPTED",
            "execution_time": (datetime.now() - start_time).total_seconds()
        }
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        print(f"[E] FAILED: Service banner vulnerability scan error - {str(e)}")
        return {
            "status": "FAILED",
            "error": str(e),
            "execution_time": execution_time
        }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python service_banner_vulns.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    result = main(target)
    print(json.dumps(result, indent=2)) 