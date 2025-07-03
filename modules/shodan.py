#!/usr/bin/env python3
"""
Improved Shodan Reconnaissance Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
UPDATED: Integrated with centralized findings system
"""

import os
import sys
import requests
import socket
from datetime import datetime

# Fix encoding issues for Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config.settings import DEFAULT_TIMEOUT, API_KEYS
    SHODAN_API_KEY = API_KEYS.get("SHODAN_API_KEY") if hasattr(API_KEYS, 'get') else None
except (ImportError, AttributeError):
    DEFAULT_TIMEOUT = 30
    SHODAN_API_KEY = None

# NEW: Import findings system
try:
    from config.findings_rules import evaluate_findings, display_findings_result
    FINDINGS_AVAILABLE = True
except ImportError:
    print("[W] Findings system not available - running in legacy mode")
    FINDINGS_AVAILABLE = False

def assess_shodan_security_risk(shodan_data, fallback_data=None):
    """Assess security risk level from Shodan data"""
    findings = []
    severity = "I"
    
    # Use Shodan data if available, otherwise fallback
    data_source = shodan_data if shodan_data else fallback_data
    
    if not data_source:
        return findings, severity
    
    # Analyze ports and services
    ports = data_source.get("ports", [])
    services = data_source.get("services", [])
    vulnerabilities = data_source.get("vulnerabilities", [])
    
    # Critical ports analysis
    critical_ports = [21, 23, 135, 139, 445, 1433, 3306, 5432, 27017, 6379, 3389]
    exposed_critical = [p for p in ports if p in critical_ports]
    
    if exposed_critical:
        findings.append(f"Critical services exposed: ports {exposed_critical}")
        severity = "C"
    
    # Industrial/IoT device detection
    industrial_keywords = ['scada', 'plc', 'modbus', 'profinet', 'ethernet/ip', 'dnp3', 'ics']
    device_tags = data_source.get("tags", [])
    
    if any(keyword in ' '.join(device_tags).lower() for keyword in industrial_keywords):
        findings.append("Industrial control system or IoT device detected")
        severity = "C"
    
    # Service analysis
    if services:
        service_names = [s.get('service', '').lower() for s in services]
        
        # Database services
        db_services = ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch']
        exposed_dbs = [s for s in service_names if any(db in s for db in db_services)]
        
        if exposed_dbs:
            findings.append(f"Database services exposed: {exposed_dbs}")
            severity = "C" if severity != "C" else "C"
        
        # Remote access services
        remote_services = ['ssh', 'rdp', 'vnc', 'telnet']
        exposed_remote = [s for s in service_names if any(remote in s for remote in remote_services)]
        
        if exposed_remote:
            findings.append(f"Remote access services: {exposed_remote}")
            if severity == "I":
                severity = "H"
    
    # Vulnerability analysis (Shodan Pro feature)
    if vulnerabilities:
        vuln_count = len(vulnerabilities)
        critical_vulns = [v for v in vulnerabilities if 'critical' in str(v).lower()]
        
        if critical_vulns:
            findings.append(f"Critical vulnerabilities detected: {len(critical_vulns)} CVEs")
            severity = "C"
        elif vuln_count > 0:
            findings.append(f"Known vulnerabilities: {vuln_count} CVEs identified")
            if severity == "I":
                severity = "H"
    
    # Large attack surface
    if len(ports) > 10:
        findings.append(f"Large attack surface: {len(ports)} open ports")
        if severity == "I":
            severity = "W"
    
    # Default finding if nothing specific detected
    if not findings and ports:
        findings.append(f"Network services identified: {len(ports)} open ports")
    
    return findings, severity

def resolve_hostname(target):
    """Resolve hostname to IP address"""
    try:
        # If target is already an IP, return as-is
        socket.inet_aton(target)
        return target, target
    except socket.error:
        # It's a hostname, resolve it
        try:
            ip_address = socket.gethostbyname(target)
            return ip_address, target
        except socket.gaierror:
            return None, target

def shodan_host_lookup(ip_address):
    """Perform Shodan host lookup"""
    if not SHODAN_API_KEY:
        return {"error": "Shodan API key required", "data": None}
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip_address}"
        params = {'key': SHODAN_API_KEY}
        
        response = requests.get(url, params=params, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code == 200:
            return {"data": response.json(), "error": None}
        elif response.status_code == 401:
            return {"error": "Invalid Shodan API key", "data": None}
        elif response.status_code == 404:
            return {"error": "No information available for this IP", "data": None}
        elif response.status_code == 429:
            return {"error": "API rate limit exceeded", "data": None}
        else:
            return {"error": f"API error: {response.status_code}", "data": None}
            
    except requests.exceptions.Timeout:
        return {"error": "Request timeout", "data": None}
    except Exception as e:
        return {"error": str(e), "data": None}

def shodan_search_query(query, limit=10):
    """Perform Shodan search query"""
    if not SHODAN_API_KEY:
        return {"error": "Shodan API key required", "results": []}
    
    try:
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            'key': SHODAN_API_KEY,
            'query': query,
            'limit': limit
        }
        
        response = requests.get(url, params=params, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            return {"results": data.get('matches', []), "total": data.get('total', 0), "error": None}
        elif response.status_code == 401:
            return {"error": "Invalid Shodan API key", "results": []}
        elif response.status_code == 429:
            return {"error": "API rate limit exceeded", "results": []}
        else:
            return {"error": f"API error: {response.status_code}", "results": []}
            
    except requests.exceptions.Timeout:
        return {"error": "Request timeout", "results": []}
    except Exception as e:
        return {"error": str(e), "results": []}

def parse_shodan_data(shodan_data):
    """Parse and organize Shodan data"""
    if not shodan_data:
        return {}
    
    parsed = {
        "ip": shodan_data.get('ip_str'),
        "organization": shodan_data.get('org'),
        "isp": shodan_data.get('isp'),
        "country": shodan_data.get('country_name'),
        "city": shodan_data.get('city'),
        "hostnames": shodan_data.get('hostnames', []),
        "ports": shodan_data.get('ports', []),
        "vulnerabilities": shodan_data.get('vulns', []),
        "tags": shodan_data.get('tags', []),
        "last_update": shodan_data.get('last_update'),
        "services": []
    }
    
    # Parse service data
    for service in shodan_data.get('data', []):
        service_info = {
            "port": service.get('port'),
            "protocol": service.get('transport', 'tcp'),
            "service": service.get('product', 'unknown'),
            "version": service.get('version'),
            "banner": service.get('data', '')[:200] if service.get('data') else '',  # Truncate banner
            "timestamp": service.get('timestamp')
        }
        parsed["services"].append(service_info)
    
    return parsed

def fallback_port_scan(ip_address):
    """Fallback basic port scan when Shodan API unavailable"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 3389, 5432, 3306]
    open_ports = []
    
    print("[I] Performing basic port scan (Shodan API unavailable)...")
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                open_ports.append({
                    "port": port,
                    "service": service,
                    "protocol": "tcp"
                })
        except:
            continue
    
    return {
        "ip": ip_address,
        "ports": [p["port"] for p in open_ports],
        "services": open_ports,
        "note": "Basic scan - limited compared to Shodan data"
    }

def perform_shodan_reconnaissance(target):
    """Perform comprehensive Shodan reconnaissance"""
    # Resolve target to IP
    ip_address, hostname = resolve_hostname(target)
    
    if not ip_address:
        return {"error": "Unable to resolve hostname", "data": None}
    
    results = {
        "target": target,
        "hostname": hostname,
        "ip_address": ip_address,
        "shodan_data": {},
        "search_results": {},
        "fallback_data": {}
    }
    
    if SHODAN_API_KEY:
        # Perform Shodan host lookup
        print(f"[I] Querying Shodan for {ip_address}...")
        host_result = shodan_host_lookup(ip_address)
        
        if host_result["error"]:
            results["shodan_data"] = {"error": host_result["error"]}
        else:
            results["shodan_data"] = parse_shodan_data(host_result["data"])
        
        # Search for related hosts/services
        if hostname != ip_address:
            print(f"[I] Searching for related hosts...")
            search_result = shodan_search_query(f'hostname:"{hostname}"', limit=5)
            results["search_results"] = search_result
    else:
        # Use fallback method
        print("[W] Shodan API key not available, using fallback scan...")
        results["fallback_data"] = fallback_port_scan(ip_address)
    
    return results

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] Shodan Reconnaissance Analysis - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("[E] FAILED: Empty target provided")
            
            # Error findings for empty target
            error_findings = {
                "success": False,
                "severity": "I",
                "findings": ["Empty target provided"],
                "has_findings": True,
                "category": "Input Error"
            }
            
            return {
                "status": "FAILED", 
                "error": "Empty target",
                "findings": error_findings,
                "execution_time": (datetime.now() - start_time).total_seconds()
            }
        
        # Check API availability
        if not SHODAN_API_KEY:
            print("[W] LIMITED: Shodan API key not configured")
            print("[I] FALLBACK: Using basic reconnaissance methods")
        
        print(f"[I] Target: {target}")
        print()
        
        # Perform reconnaissance (your existing logic)
        results = perform_shodan_reconnaissance(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Check for resolution errors
        if results.get("error"):
            print(f"[E] ERROR: {results['error']}")
            
            # Error findings for resolution failure
            error_findings = {
                "success": False,
                "severity": "I",
                "findings": [f"Target resolution failed: {results['error']}"],
                "has_findings": True,
                "category": "Network Error"
            }
            
            return {
                "status": "FAILED",
                "error": results["error"],
                "findings": error_findings,
                "execution_time": execution_time
            }
        
        # Prepare scan data for findings evaluation
        shodan_data = results.get("shodan_data", {})
        fallback_data = results.get("fallback_data", {})
        search_results = results.get("search_results", {})
        
        # Determine data source and prepare scan data
        if shodan_data and not shodan_data.get("error"):
            # Full Shodan data available
            scan_data = {
                "ip_address": results["ip_address"],
                "hostname": results["hostname"],
                "ports": shodan_data.get("ports", []),
                "services": shodan_data.get("services", []),
                "vulnerabilities": shodan_data.get("vulnerabilities", []),
                "organization": shodan_data.get("organization"),
                "tags": shodan_data.get("tags", []),
                "api_available": True,
                "data_source": "shodan",
                "scan_completed": True
            }
            data_source = shodan_data
        elif fallback_data and fallback_data.get("ports"):
            # Fallback data available
            scan_data = {
                "ip_address": results["ip_address"], 
                "hostname": results["hostname"],
                "ports": fallback_data.get("ports", []),
                "services": fallback_data.get("services", []),
                "vulnerabilities": [],
                "organization": None,
                "tags": [],
                "api_available": False,
                "data_source": "fallback",
                "scan_completed": True
            }
            data_source = fallback_data
        else:
            # No data available
            scan_data = {
                "ip_address": results.get("ip_address"),
                "hostname": results.get("hostname"),
                "ports": [],
                "services": [],
                "vulnerabilities": [],
                "api_available": SHODAN_API_KEY is not None,
                "data_source": "none",
                "scan_completed": True
            }
            data_source = None
        
        # Analyze results and display (keep existing logic)
        if shodan_data and not shodan_data.get("error"):
            # Shodan data available - perform security assessment
            security_findings, severity = assess_shodan_security_risk(shodan_data)
            
            ports = shodan_data.get("ports", [])
            services = shodan_data.get("services", [])
            vulns = shodan_data.get("vulnerabilities", [])
            
            print(f"[{severity}] SHODAN DATA: Found comprehensive intelligence for {results['ip_address']}")
            
            # Display legacy security analysis
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display basic info (keep existing display)
            print("[I] Host Information:")
            print(f"  [I] IP Address: {shodan_data.get('ip')}")
            if shodan_data.get('organization'):
                print(f"  [I] Organization: {shodan_data.get('organization')}")
            if shodan_data.get('isp'):
                print(f"  [I] ISP: {shodan_data.get('isp')}")
            if shodan_data.get('country'):
                print(f"  [I] Location: {shodan_data.get('city', 'Unknown')}, {shodan_data.get('country')}")
            print()
            
            # Display services
            if services:
                print(f"[I] SERVICES ({len(services)}):")
                for service in services[:10]:  # Show first 10
                    port_risk = "C" if service['port'] in [21, 23, 135, 139, 445, 3389] else "I"
                    version_info = f" v{service['version']}" if service.get('version') else ""
                    print(f"  [{port_risk}] Port {service['port']}: {service['service']}{version_info}")
                if len(services) > 10:
                    print(f"  [I] ... and {len(services) - 10} more services")
                print()
            
            # Display vulnerabilities
            if vulns:
                print(f"[C] VULNERABILITIES ({len(vulns)}):")
                for vuln in vulns[:5]:  # Show first 5
                    print(f"  [C] {vuln}")
                if len(vulns) > 5:
                    print(f"  [C] ... and {len(vulns) - 5} more vulnerabilities")
                print()
            
            # Display hostnames
            hostnames = shodan_data.get('hostnames', [])
            if hostnames:
                print(f"[I] HOSTNAMES ({len(hostnames)}):")
                for hostname in hostnames[:5]:
                    print(f"  [I] {hostname}")
                if len(hostnames) > 5:
                    print(f"  [I] ... and {len(hostnames) - 5} more hostnames")
                print()
            
        elif fallback_data and fallback_data.get("ports"):
            # Fallback data available
            security_findings, severity = assess_shodan_security_risk(None, fallback_data)
            
            ports = fallback_data.get("ports", [])
            services = fallback_data.get("services", [])
            
            print(f"[{severity}] BASIC SCAN: Found {len(ports)} open ports on {results['ip_address']}")
            
            if security_findings:
                print(f"[{severity}] Security Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            print("[I] Open Ports (Basic Scan):")
            for service in services:
                port_risk = "C" if service['port'] in [21, 23, 135, 139, 445, 3389] else "I"
                print(f"  [{port_risk}] Port {service['port']}: {service['service']}")
            print()
            print("[I] NOTE: Limited data - Shodan API provides comprehensive vulnerability intelligence")
            
        else:
            # Handle API errors or no data
            if shodan_data and shodan_data.get("error"):
                error_msg = shodan_data["error"]
                if "API key" in error_msg:
                    print("[E] API ERROR: Invalid or missing Shodan API key")
                    print("[I] SETUP: Configure SHODAN_API_KEY in config/settings.py")
                elif "rate limit" in error_msg.lower():
                    print("[W] RATE LIMIT: Shodan API rate limit exceeded")
                elif "No information" in error_msg:
                    print("[I] NO DATA: No Shodan intelligence available for this target")
                else:
                    print(f"[E] ERROR: {error_msg}")
            else:
                print("[I] NO DATA: No reconnaissance intelligence found")
            
            security_findings = []
            severity = "I"
        
        print()
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("shodan.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            if data_source:
                findings = security_findings if security_findings else ["Network reconnaissance completed"]
                has_findings = len(security_findings) > 0 or len(scan_data.get("ports", [])) > 0
            else:
                findings = ["No reconnaissance data available"]
                has_findings = False
            
            findings_result = {
                "success": True,  # Scan completed successfully
                "severity": severity,
                "findings": findings,
                "has_findings": has_findings,
                "category": "Network Reconnaissance"
            }
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        print()
        
        # Return standardized format
        return {
            "status": "SUCCESS",  # Always success if scan completes
            "data": scan_data,
            "findings": findings_result,
            "execution_time": execution_time,
            "target": target,
            # Keep legacy fields for backward compatibility
            "count": len(scan_data.get("ports", [])) + len(scan_data.get("services", [])) + len(scan_data.get("vulnerabilities", [])),
            "security_findings": security_findings if 'security_findings' in locals() else [],
            "severity": findings_result["severity"]
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Reconnaissance stopped by user")
        
        interrupt_findings = {
            "success": False,
            "severity": "I",
            "findings": ["Shodan reconnaissance interrupted by user"],
            "has_findings": True,
            "category": "Execution"
        }
        
        return {
            "status": "INTERRUPTED",
            "findings": interrupt_findings,
            "execution_time": (datetime.now() - start_time).total_seconds()
        }
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        # Classify error types
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during reconnaissance")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("[E] ERROR: Connection error during API requests")
            status = "CONNECTION_ERROR"
        else:
            print(f"[E] ERROR: {error_msg}")
            status = "ERROR"
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        
        # Error findings
        error_findings = {
            "success": False,
            "severity": "I",
            "findings": [f"Shodan reconnaissance failed: {error_msg}"],
            "has_findings": True,
            "category": "Error"
        }
        
        return {
            "status": status,
            "error": error_msg,
            "findings": error_findings,
            "execution_time": execution_time
        }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        result = main(target)
        
        # Exit with appropriate code
        exit_code = 0 if result["status"] in ["SUCCESS", "INTERRUPTED"] else 1
        sys.exit(exit_code)
    else:
        print("[E] ERROR: No target provided")
        print("Usage: python shodan.py <ip_or_domain>")
        print("Example: python shodan.py example.com")
        print()
        print("Note: Requires Shodan API key for comprehensive vulnerability intelligence")
        sys.exit(1)