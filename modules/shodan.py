#!/usr/bin/env python3
"""
Improved Shodan Module - Clean Output with Success/Failure Indicators
Note: This module requires a Shodan API key for full functionality
"""

import os
import sys
import requests
import socket
from datetime import datetime
import json

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DEFAULT_TIMEOUT

# Try to import API keys
try:
    from config.settings import API_KEYS
    SHODAN_API_KEY = API_KEYS.get("SHODAN_API_KEY")
except (ImportError, AttributeError):
    SHODAN_API_KEY = None

def resolve_hostname(target):
    """Resolve hostname to IP address"""
    try:
        # Remove protocol if present
        hostname = target.replace('http://', '').replace('https://', '').split('/')[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address, hostname
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
    
    print("🔄 Performing basic port scan (Shodan API unavailable)...")
    
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
        print(f"🔍 Querying Shodan for {ip_address}...")
        host_result = shodan_host_lookup(ip_address)
        
        if host_result["error"]:
            results["shodan_data"] = {"error": host_result["error"]}
        else:
            results["shodan_data"] = parse_shodan_data(host_result["data"])
        
        # Search for related hosts/services
        if hostname != ip_address:
            print(f"🔍 Searching for related hosts...")
            search_result = shodan_search_query(f'hostname:"{hostname}"', limit=5)
            results["search_results"] = search_result
    else:
        # Use fallback method
        print("🔑 Shodan API key not available, using fallback scan...")
        results["fallback_data"] = fallback_port_scan(ip_address)
    
    return results

def main(target):
    """Main execution with clean output"""
    print(f"🔍 Shodan Reconnaissance - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("❌ FAILED: Empty target provided")
            return {"status": "FAILED", "error": "Empty target"}
        
        # Check API availability
        if not SHODAN_API_KEY:
            print("🔑 LIMITED: Shodan API key not configured")
            print("ℹ️  FALLBACK: Using basic reconnaissance methods")
        
        print(f"🎯 Target: {target}")
        print()
        
        # Perform reconnaissance
        results = perform_shodan_reconnaissance(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Check for resolution errors
        if results.get("error"):
            print(f"❌ ERROR: {results['error']}")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": "FAILED", "error": results["error"], "execution_time": execution_time}
        
        # Analyze results
        shodan_data = results.get("shodan_data", {})
        fallback_data = results.get("fallback_data", {})
        search_results = results.get("search_results", {})
        
        if shodan_data and not shodan_data.get("error"):
            # Shodan data available
            ports = shodan_data.get("ports", [])
            services = shodan_data.get("services", [])
            vulns = shodan_data.get("vulnerabilities", [])
            
            print(f"✅ SUCCESS: Found Shodan data for {results['ip_address']}")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Display basic info
            print("🏢 Host Information:")
            print(f"   • IP Address: {shodan_data.get('ip')}")
            if shodan_data.get('organization'):
                print(f"   • Organization: {shodan_data.get('organization')}")
            if shodan_data.get('isp'):
                print(f"   • ISP: {shodan_data.get('isp')}")
            if shodan_data.get('country'):
                location = shodan_data.get('city', '') + ', ' + shodan_data.get('country', '')
                print(f"   • Location: {location.strip(', ')}")
            print()
            
            # Display ports and services
            if ports:
                print(f"🔓 Open Ports ({len(ports)}):")
                for port in sorted(ports)[:10]:  # Show first 10
                    print(f"   • {port}")
                print()
            
            if services:
                print(f"🖥️ Services ({len(services)}):")
                for service in services[:5]:  # Show first 5
                    service_name = service.get('service', 'unknown')
                    version = service.get('version', '')
                    version_str = f" {version}" if version else ""
                    print(f"   • Port {service.get('port')}: {service_name}{version_str}")
                print()
            
            # Display vulnerabilities
            if vulns:
                print(f"⚠️ Vulnerabilities ({len(vulns)}):")
                for vuln in vulns[:5]:  # Show first 5
                    print(f"   • {vuln}")
                print()
            
            # Display hostnames
            hostnames = shodan_data.get('hostnames', [])
            if hostnames:
                print(f"🌐 Hostnames ({len(hostnames)}):")
                for hostname in hostnames[:5]:
                    print(f"   • {hostname}")
                print()
            
            return {
                "status": "SUCCESS",
                "data": results,
                "count": len(ports) + len(services) + len(vulns),
                "execution_time": execution_time,
                "severity": "HIGH" if vulns else "MEDIUM" if services else "LOW"
            }
        
        elif fallback_data and fallback_data.get("ports"):
            # Fallback data available
            ports = fallback_data.get("ports", [])
            services = fallback_data.get("services", [])
            
            print(f"✅ BASIC SCAN: Found {len(ports)} open ports on {results['ip_address']}")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            print("🔓 Open Ports (Basic Scan):")
            for service in services:
                print(f"   • Port {service['port']}: {service['service']}")
            print()
            print("ℹ️  NOTE: Limited data - Shodan API provides comprehensive information")
            
            return {
                "status": "LIMITED",
                "data": results,
                "count": len(ports),
                "execution_time": execution_time,
                "note": "Basic scan only - API key required for full data"
            }
        
        elif shodan_data.get("error"):
            # Shodan API error
            error_msg = shodan_data["error"]
            if "API key" in error_msg:
                print("🔑 API ERROR: Invalid or missing Shodan API key")
                print("ℹ️  SETUP: Configure SHODAN_API_KEY in config/settings.py")
                status = "API_ERROR"
            elif "rate limit" in error_msg.lower():
                print("⏰ RATE LIMIT: Shodan API rate limit exceeded")
                status = "RATE_LIMITED"
            elif "No information" in error_msg:
                print("ℹ️  NO DATA: No Shodan data available for this target")
                status = "NO_DATA"
            else:
                print(f"❌ ERROR: {error_msg}")
                status = "ERROR"
            
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": status, "error": error_msg, "execution_time": execution_time}
        
        else:
            print("ℹ️  NO DATA: No reconnaissance data found")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Reconnaissance stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("⏰ TIMEOUT: Request timeout during reconnaissance")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("🌐 ERROR: Connection error during API requests")
            status = "CONNECTION_ERROR"
        else:
            print(f"❌ ERROR: {error_msg}")
            status = "ERROR"
        
        print(f"⏱️  Execution time: {execution_time:.2f}s")
        return {"status": status, "error": error_msg, "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print("❌ ERROR: No target provided")
        print("Usage: python shodan.py <ip_or_domain>")
        print("Example: python shodan.py example.com")
        print()
        print("Note: Requires Shodan API key for comprehensive data")
        sys.exit(1)