#!/usr/bin/env python3
"""
API Security Scanner Module
Performs comprehensive API security testing including authentication bypass, 
parameter manipulation, rate limiting bypass, and OWASP API Top 10 vulnerabilities.
"""

import os
import sys
import requests
import json
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

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

def get_api_endpoints():
    """Get common API endpoints to test"""
    return [
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/rest/",
        "/rest/api/",
        "/graphql",
        "/swagger/",
        "/swagger-ui/",
        "/swagger.json",
        "/api-docs/",
        "/api-docs.json",
        "/openapi.json",
        "/openapi.yaml",
        "/docs/",
        "/redoc/",
        "/api/users",
        "/api/admin",
        "/api/auth",
        "/api/login",
        "/api/register",
        "/api/profile",
        "/api/settings",
        "/api/config",
        "/api/health",
        "/api/status"
    ]

def get_api_test_payloads():
    """Get API security test payloads"""
    return {
        "authentication_bypass": [
            {"Authorization": ""},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"Authorization": "Bearer "},
            {"X-API-Key": ""},
            {"X-API-Key": "null"},
            {"X-API-Key": "undefined"},
            {"X-API-Key": "test"},
            {"X-API-Key": "admin"},
            {"X-API-Key": "123456"},
            {"X-Auth-Token": ""},
            {"X-Auth-Token": "null"},
            {"X-Auth-Token": "test"},
            {"X-Auth-Token": "admin"}
        ],
        "parameter_manipulation": [
            {"id": "1"},
            {"id": "1'"},
            {"id": "1 OR 1=1"},
            {"id": "1; DROP TABLE users"},
            {"id": "1 UNION SELECT * FROM users"},
            {"user_id": "1"},
            {"user_id": "admin"},
            {"user_id": "1' OR '1'='1"},
            {"email": "test@example.com"},
            {"email": "admin@example.com"},
            {"email": "test@example.com' OR '1'='1"},
            {"username": "test"},
            {"username": "admin"},
            {"username": "test' OR '1'='1"}
        ],
        "rate_limiting_bypass": [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "192.168.1.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Real-IP": "192.168.1.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Client-IP": "192.168.1.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "192.168.1.1"}
        ],
        "injection_payloads": [
            {"query": "test"},
            {"query": "test'"},
            {"query": "test' OR '1'='1"},
            {"query": "test; DROP TABLE users"},
            {"query": "test UNION SELECT * FROM users"},
            {"search": "test"},
            {"search": "test'"},
            {"search": "test' OR '1'='1"},
            {"filter": "test"},
            {"filter": "test'"},
            {"filter": "test' OR '1'='1"}
        ]
    }

def discover_api_endpoints(target):
    """Discover API endpoints on the target"""
    endpoints = []
    
    # Try common protocols
    protocols = ["https", "http"]
    
    for protocol in protocols:
        base_url = f"{protocol}://{target}"
        
        # Test common API endpoints
        api_endpoints = get_api_endpoints()
        
        for endpoint in api_endpoints:
            try:
                url = urljoin(base_url, endpoint)
                headers = {
                    'User-Agent': USER_AGENT,
                    'Accept': 'application/json,text/html,application/xml;q=0.9,*/*;q=0.8',
                }
                
                response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
                
                if response.status_code in [200, 401, 403, 404, 405]:
                    endpoints.append({
                        "url": url,
                        "status_code": response.status_code,
                        "content_type": response.headers.get('content-type', ''),
                        "content_length": len(response.text)
                    })
            
            except Exception as e:
                continue
    
    return endpoints

def test_authentication_bypass(endpoint_info):
    """Test for authentication bypass vulnerabilities"""
    vulnerabilities = []
    url = endpoint_info["url"]
    
    # Skip if endpoint returns 404
    if endpoint_info["status_code"] == 404:
        return vulnerabilities
    
    payloads = get_api_test_payloads()["authentication_bypass"]
    
    for payload in payloads:
        try:
            headers = {
                'User-Agent': USER_AGENT,
                'Accept': 'application/json,text/html,application/xml;q=0.9,*/*;q=0.8',
            }
            headers.update(payload)
            
            response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            
            # Check if authentication bypass was successful
            if response.status_code == 200 and len(response.text) > 50:
                vulnerabilities.append({
                    "url": url,
                    "vulnerability": "Authentication Bypass",
                    "payload": payload,
                    "response_code": response.status_code,
                    "response_length": len(response.text),
                    "severity": "high",
                    "description": f"Authentication bypassed with payload: {payload}"
                })
        
        except Exception as e:
            continue
    
    return vulnerabilities

def test_parameter_manipulation(endpoint_info):
    """Test for parameter manipulation vulnerabilities"""
    vulnerabilities = []
    url = endpoint_info["url"]
    
    # Skip if endpoint returns 404
    if endpoint_info["status_code"] == 404:
        return vulnerabilities
    
    payloads = get_api_test_payloads()["parameter_manipulation"]
    
    for payload in payloads:
        try:
            headers = {
                'User-Agent': USER_AGENT,
                'Accept': 'application/json,text/html,application/xml;q=0.9,*/*;q=0.8',
            }
            
            # Test GET request with parameters
            test_url = f"{url}?{urlencode(payload)}"
            response = requests.get(test_url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            
            # Check for successful parameter manipulation
            if response.status_code == 200 and len(response.text) > 50:
                vulnerabilities.append({
                    "url": test_url,
                    "vulnerability": "Parameter Manipulation",
                    "payload": payload,
                    "response_code": response.status_code,
                    "response_length": len(response.text),
                    "severity": "medium",
                    "description": f"Parameter manipulation successful with payload: {payload}"
                })
            
            # Test POST request with parameters
            response = requests.post(url, data=payload, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            
            if response.status_code == 200 and len(response.text) > 50:
                vulnerabilities.append({
                    "url": url,
                    "vulnerability": "Parameter Manipulation",
                    "payload": payload,
                    "method": "POST",
                    "response_code": response.status_code,
                    "response_length": len(response.text),
                    "severity": "medium",
                    "description": f"Parameter manipulation successful with POST payload: {payload}"
                })
        
        except Exception as e:
            continue
    
    return vulnerabilities

def test_rate_limiting_bypass(endpoint_info):
    """Test for rate limiting bypass vulnerabilities"""
    vulnerabilities = []
    url = endpoint_info["url"]
    
    # Skip if endpoint returns 404
    if endpoint_info["status_code"] == 404:
        return vulnerabilities
    
    payloads = get_api_test_payloads()["rate_limiting_bypass"]
    
    # First, establish baseline rate limit
    baseline_requests = []
    for i in range(5):
        try:
            headers = {
                'User-Agent': USER_AGENT,
                'Accept': 'application/json,text/html,application/xml;q=0.9,*/*;q=0.8',
            }
            
            response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            baseline_requests.append(response.status_code)
            time.sleep(0.1)
        
        except Exception:
            continue
    
    # Check if rate limiting is active
    rate_limited = any(code == 429 for code in baseline_requests)
    
    if rate_limited:
        # Test bypass techniques
        for payload in payloads:
            try:
                headers = {
                    'User-Agent': USER_AGENT,
                    'Accept': 'application/json,text/html,application/xml;q=0.9,*/*;q=0.8',
                }
                headers.update(payload)
                
                response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
                
                # Check if bypass was successful
                if response.status_code == 200:
                    vulnerabilities.append({
                        "url": url,
                        "vulnerability": "Rate Limiting Bypass",
                        "payload": payload,
                        "response_code": response.status_code,
                        "severity": "medium",
                        "description": f"Rate limiting bypassed with payload: {payload}"
                    })
            
            except Exception as e:
                continue
    
    return vulnerabilities

def test_injection_vulnerabilities(endpoint_info):
    """Test for injection vulnerabilities"""
    vulnerabilities = []
    url = endpoint_info["url"]
    
    # Skip if endpoint returns 404
    if endpoint_info["status_code"] == 404:
        return vulnerabilities
    
    payloads = get_api_test_payloads()["injection_payloads"]
    
    for payload in payloads:
        try:
            headers = {
                'User-Agent': USER_AGENT,
                'Accept': 'application/json,text/html,application/xml;q=0.9,*/*;q=0.8',
            }
            
            # Test GET request
            test_url = f"{url}?{urlencode(payload)}"
            response = requests.get(test_url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            
            # Check for injection indicators
            if detect_injection_success(response.text, payload):
                vulnerabilities.append({
                    "url": test_url,
                    "vulnerability": "Injection Vulnerability",
                    "payload": payload,
                    "response_code": response.status_code,
                    "severity": "high",
                    "description": f"Injection vulnerability detected with payload: {payload}"
                })
            
            # Test POST request
            response = requests.post(url, data=payload, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            
            if detect_injection_success(response.text, payload):
                vulnerabilities.append({
                    "url": url,
                    "vulnerability": "Injection Vulnerability",
                    "payload": payload,
                    "method": "POST",
                    "response_code": response.status_code,
                    "severity": "high",
                    "description": f"Injection vulnerability detected with POST payload: {payload}"
                })
        
        except Exception as e:
            continue
    
    return vulnerabilities

def detect_injection_success(response_text, payload):
    """Detect successful injection in response"""
    # Check for SQL error messages
    sql_errors = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "SQLite",
        "Microsoft SQL",
        "ODBC",
        "JDBC"
    ]
    
    for error in sql_errors:
        if error.lower() in response_text.lower():
            return True
    
    # Check for payload reflection
    if any(key in payload for key in ["'", "OR", "UNION", "DROP", "SELECT"]):
        if payload.get("query", "") in response_text or payload.get("search", "") in response_text:
            return True
    
    return False

def test_api_methods(endpoint_info):
    """Test for unauthorized API methods"""
    vulnerabilities = []
    url = endpoint_info["url"]
    
    # Skip if endpoint returns 404
    if endpoint_info["status_code"] == 404:
        return vulnerabilities
    
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    
    for method in methods:
        try:
            headers = {
                'User-Agent': USER_AGENT,
                'Accept': 'application/json,text/html,application/xml;q=0.9,*/*;q=0.8',
            }
            
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            elif method == "POST":
                response = requests.post(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            elif method == "PUT":
                response = requests.put(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            elif method == "PATCH":
                response = requests.patch(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            elif method == "OPTIONS":
                response = requests.options(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            elif method == "HEAD":
                response = requests.head(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
            
            # Check if method is allowed but should be restricted
            if response.status_code in [200, 201, 204]:
                vulnerabilities.append({
                    "url": url,
                    "vulnerability": "Unauthorized Method",
                    "method": method,
                    "response_code": response.status_code,
                    "severity": "medium",
                    "description": f"Unauthorized {method} method allowed"
                })
        
        except Exception as e:
            continue
    
    return vulnerabilities

def scan_api_endpoint(endpoint_info):
    """Scan a specific API endpoint for vulnerabilities"""
    vulnerabilities = []
    
    # Test various API vulnerabilities
    tests = [
        test_authentication_bypass,
        test_parameter_manipulation,
        test_rate_limiting_bypass,
        test_injection_vulnerabilities,
        test_api_methods
    ]
    
    for test_func in tests:
        try:
            test_vulns = test_func(endpoint_info)
            vulnerabilities.extend(test_vulns)
        except Exception as e:
            print(f"[E] Error testing endpoint {endpoint_info['url']}: {str(e)}")
    
    return vulnerabilities

def perform_api_security_scan(target):
    """Perform comprehensive API security scan"""
    print(f"[I] Starting API security scan for {target}")
    
    # Discover API endpoints
    endpoints = discover_api_endpoints(target)
    
    if not endpoints:
        print(f"[W] No API endpoints discovered for {target}")
        return {
            "target": target,
            "endpoints_discovered": 0,
            "vulnerabilities_found": 0,
            "scan_time": datetime.now().isoformat()
        }
    
    print(f"[I] Discovered {len(endpoints)} API endpoints")
    
    # Scan each endpoint for vulnerabilities
    all_vulnerabilities = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_endpoint = {executor.submit(scan_api_endpoint, endpoint): endpoint for endpoint in endpoints}
        
        for future in as_completed(future_to_endpoint):
            endpoint = future_to_endpoint[future]
            try:
                vulnerabilities = future.result()
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                print(f"[E] Error scanning endpoint {endpoint['url']}: {str(e)}")
    
    return {
        "target": target,
        "endpoints_discovered": len(endpoints),
        "endpoints_scanned": len(endpoints),
        "vulnerabilities_found": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities,
        "scan_time": datetime.now().isoformat()
    }

def assess_api_vulnerability_risk(results):
    """Assess security risk level of API vulnerability findings"""
    findings = []
    severity = "I"
    
    vulnerabilities = results.get("vulnerabilities", [])
    endpoints_discovered = results.get("endpoints_discovered", 0)
    
    if not vulnerabilities:
        return findings, severity
    
    # Count vulnerabilities by type
    auth_bypass = len([v for v in vulnerabilities if v.get("vulnerability") == "Authentication Bypass"])
    param_manipulation = len([v for v in vulnerabilities if v.get("vulnerability") == "Parameter Manipulation"])
    rate_limit_bypass = len([v for v in vulnerabilities if v.get("vulnerability") == "Rate Limiting Bypass"])
    injection = len([v for v in vulnerabilities if v.get("vulnerability") == "Injection Vulnerability"])
    unauthorized_method = len([v for v in vulnerabilities if v.get("vulnerability") == "Unauthorized Method"])
    
    # High findings - Authentication bypass and injection
    if auth_bypass > 0:
        severity = "H"
        findings.append(f"High-risk API vulnerabilities: {auth_bypass} authentication bypass issues detected")
        
        # List high vulnerabilities
        high_vulns = [v for v in vulnerabilities if v.get("vulnerability") == "Authentication Bypass"]
        for vuln in high_vulns[:3]:  # Show first 3
            url = vuln.get("url", "Unknown")
            findings.append(f"High: Authentication bypass at {url}")
    
    if injection > 0:
        if severity == "I":
            severity = "H"
        findings.append(f"High-risk API vulnerabilities: {injection} injection vulnerabilities detected")
    
    # Medium findings - Parameter manipulation and rate limiting bypass
    if param_manipulation > 0:
        if severity == "I":
            severity = "M"
        findings.append(f"Medium-risk API vulnerabilities: {param_manipulation} parameter manipulation issues detected")
    
    if rate_limit_bypass > 0:
        if severity == "I":
            severity = "M"
        findings.append(f"Medium-risk API vulnerabilities: {rate_limit_bypass} rate limiting bypass issues detected")
    
    if unauthorized_method > 0:
        if severity == "I":
            severity = "M"
        findings.append(f"Medium-risk API vulnerabilities: {unauthorized_method} unauthorized method access issues detected")
    
    # Overall assessment
    total_vulns = len(vulnerabilities)
    if total_vulns > 5:
        if severity not in ["H", "C"]:
            severity = "H"
        findings.append(f"Multiple API vulnerabilities: {total_vulns} security issues across {endpoints_discovered} endpoints")
    
    return findings, severity

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] API Security Scanner - {target}")
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
        
        # Perform API security scan
        results = perform_api_security_scan(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Prepare scan data for findings evaluation
        vulnerabilities = results.get("vulnerabilities", [])
        endpoints_discovered = results.get("endpoints_discovered", 0)
        
        scan_data = {
            "target": target,
            "endpoints_discovered": endpoints_discovered,
            "vulnerabilities_found": len(vulnerabilities),
            "authentication_bypass_vulnerabilities": len([v for v in vulnerabilities if v.get("vulnerability") == "Authentication Bypass"]),
            "parameter_manipulation_vulnerabilities": len([v for v in vulnerabilities if v.get("vulnerability") == "Parameter Manipulation"]),
            "rate_limiting_bypass_vulnerabilities": len([v for v in vulnerabilities if v.get("vulnerability") == "Rate Limiting Bypass"]),
            "injection_vulnerabilities": len([v for v in vulnerabilities if v.get("vulnerability") == "Injection Vulnerability"]),
            "unauthorized_method_vulnerabilities": len([v for v in vulnerabilities if v.get("vulnerability") == "Unauthorized Method"]),
            "vulnerabilities": vulnerabilities,
            "status": "SUCCESS" if vulnerabilities else "NO_DATA",
            "scan_completed": True
        }
        
        if vulnerabilities:
            # Assess security risk
            security_findings, severity = assess_api_vulnerability_risk(results)
            
            print(f"[{severity}] API VULNERABILITIES FOUND: {len(vulnerabilities)} security issues detected across {endpoints_discovered} endpoints")
            
            # Display vulnerability summary
            print(f"[{severity}] Vulnerability Summary:")
            auth_count = len([v for v in vulnerabilities if v.get("vulnerability") == "Authentication Bypass"])
            param_count = len([v for v in vulnerabilities if v.get("vulnerability") == "Parameter Manipulation"])
            rate_count = len([v for v in vulnerabilities if v.get("vulnerability") == "Rate Limiting Bypass"])
            inj_count = len([v for v in vulnerabilities if v.get("vulnerability") == "Injection Vulnerability"])
            method_count = len([v for v in vulnerabilities if v.get("vulnerability") == "Unauthorized Method"])
            
            if auth_count > 0:
                print(f"  [H] Authentication Bypass: {auth_count}")
            if inj_count > 0:
                print(f"  [H] Injection: {inj_count}")
            if param_count > 0:
                print(f"  [M] Parameter Manipulation: {param_count}")
            if rate_count > 0:
                print(f"  [M] Rate Limiting Bypass: {rate_count}")
            if method_count > 0:
                print(f"  [M] Unauthorized Methods: {method_count}")
            print()
            
            # Display vulnerable endpoints
            if vulnerabilities:
                print(f"[I] VULNERABLE ENDPOINTS ({len(vulnerabilities)}):")
                for vuln in vulnerabilities[:10]:  # Show first 10
                    url = vuln.get("url", "Unknown")
                    vuln_type = vuln.get("vulnerability", "Unknown")
                    description = vuln.get("description", "No description")
                    vuln_severity = vuln.get("severity", "medium")
                    
                    print(f"  [{vuln_severity.upper()}] {url} - {vuln_type}: {description}")
                
                if len(vulnerabilities) > 10:
                    print(f"  [I] ... and {len(vulnerabilities) - 10} more vulnerabilities")
                print()
            
            # Display security findings
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
        else:
            print("[I] NO DATA: No API vulnerabilities found")
            security_findings = []
            severity = "I"
        
        print()
        
        # Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("api_security_scanner.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            if vulnerabilities:
                findings = security_findings if security_findings else [f"Found {len(vulnerabilities)} API vulnerabilities"]
            else:
                findings = ["No API vulnerabilities detected"]
            
            findings_result = {
                "success": len(vulnerabilities) > 0,
                "severity": severity,
                "findings": findings,
                "has_findings": len(vulnerabilities) > 0,
                "category": "API Security Assessment"
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
            "vulnerabilities": vulnerabilities,
            "endpoints_discovered": endpoints_discovered,
            "severity": findings_result["severity"]
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: API security scan stopped by user")
        return {
            "status": "INTERRUPTED",
            "execution_time": (datetime.now() - start_time).total_seconds()
        }
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        print(f"[E] FAILED: API security scan error - {str(e)}")
        return {
            "status": "FAILED",
            "error": str(e),
            "execution_time": execution_time
        }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python api_security_scanner.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    result = main(target)
    print(json.dumps(result, indent=2)) 