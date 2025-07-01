#!/usr/bin/env python3
"""
Default Credentials Scanner Module
Tests discovered services for default, weak, or commonly used credentials across 
databases, web interfaces, IoT devices, and network equipment.
"""

import os
import sys
import socket
import requests
import json
import re
import ftplib
import telnetlib
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

def get_default_credentials_database():
    """Get database of default credentials for various services"""
    return {
        "SSH": [
            {"username": "root", "password": ""},
            {"username": "root", "password": "root"},
            {"username": "root", "password": "admin"},
            {"username": "root", "password": "password"},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": ""},
            {"username": "root", "password": "123456"},
            {"username": "admin", "password": "123456"},
            {"username": "pi", "password": "raspberry"},
            {"username": "ubuntu", "password": "ubuntu"},
            {"username": "debian", "password": "debian"},
            {"username": "centos", "password": "centos"},
            {"username": "fedora", "password": "fedora"}
        ],
        "FTP": [
            {"username": "anonymous", "password": ""},
            {"username": "anonymous", "password": "anonymous"},
            {"username": "ftp", "password": "ftp"},
            {"username": "admin", "password": "admin"},
            {"username": "root", "password": "root"},
            {"username": "guest", "password": "guest"},
            {"username": "user", "password": "user"},
            {"username": "test", "password": "test"}
        ],
        "Telnet": [
            {"username": "root", "password": ""},
            {"username": "root", "password": "root"},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": ""},
            {"username": "cisco", "password": "cisco"},
            {"username": "admin", "password": "password"}
        ],
        "HTTP": [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": ""},
            {"username": "root", "password": "root"},
            {"username": "root", "password": "admin"},
            {"username": "administrator", "password": "administrator"},
            {"username": "administrator", "password": "admin"},
            {"username": "user", "password": "user"},
            {"username": "guest", "password": "guest"},
            {"username": "test", "password": "test"},
            {"username": "demo", "password": "demo"},
            {"username": "webmaster", "password": "webmaster"},
            {"username": "manager", "password": "manager"},
            {"username": "operator", "password": "operator"}
        ],
        "MySQL": [
            {"username": "root", "password": ""},
            {"username": "root", "password": "root"},
            {"username": "root", "password": "mysql"},
            {"username": "root", "password": "password"},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": ""},
            {"username": "mysql", "password": "mysql"},
            {"username": "user", "password": "user"}
        ],
        "PostgreSQL": [
            {"username": "postgres", "password": ""},
            {"username": "postgres", "password": "postgres"},
            {"username": "postgres", "password": "password"},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": ""}
        ],
        "Redis": [
            {"username": "", "password": ""},
            {"username": "default", "password": ""},
            {"username": "redis", "password": "redis"}
        ],
        "MongoDB": [
            {"username": "", "password": ""},
            {"username": "admin", "password": ""},
            {"username": "admin", "password": "admin"},
            {"username": "root", "password": ""},
            {"username": "root", "password": "root"}
        ],
        "RDP": [
            {"username": "administrator", "password": ""},
            {"username": "administrator", "password": "administrator"},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": ""},
            {"username": "root", "password": "root"},
            {"username": "guest", "password": ""},
            {"username": "guest", "password": "guest"}
        ],
        "VNC": [
            {"username": "", "password": ""},
            {"username": "admin", "password": "admin"},
            {"username": "root", "password": "root"},
            {"username": "vnc", "password": "vnc"},
            {"username": "password", "password": "password"}
        ]
    }

def get_common_service_ports():
    """Get list of common service ports to test"""
    return {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTP",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP",
        8443: "HTTP"
    }

def test_ssh_credentials(target, port, credentials):
    """Test SSH credentials"""
    try:
        import paramiko
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        username = credentials["username"]
        password = credentials["password"]
        
        ssh.connect(target, port=port, username=username, password=password, timeout=5)
        ssh.close()
        
        return True, f"SSH login successful with {username}:{password}"
    
    except ImportError:
        # Fallback without paramiko
        return False, "Paramiko not available for SSH testing"
    except Exception as e:
        return False, str(e)

def test_ftp_credentials(target, port, credentials):
    """Test FTP credentials"""
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=5)
        
        username = credentials["username"]
        password = credentials["password"]
        
        ftp.login(username, password)
        ftp.quit()
        
        return True, f"FTP login successful with {username}:{password}"
    
    except Exception as e:
        return False, str(e)

def test_telnet_credentials(target, port, credentials):
    """Test Telnet credentials"""
    try:
        tn = telnetlib.Telnet(target, port, timeout=5)
        
        username = credentials["username"]
        password = credentials["password"]
        
        # Read initial prompt
        tn.read_until(b"login: ", timeout=5)
        tn.write(username.encode('ascii') + b"\n")
        
        tn.read_until(b"Password: ", timeout=5)
        tn.write(password.encode('ascii') + b"\n")
        
        # Check for successful login
        result = tn.read_very_eager().decode('ascii')
        tn.close()
        
        if "incorrect" not in result.lower() and "failed" not in result.lower():
            return True, f"Telnet login successful with {username}:{password}"
        
        return False, "Login failed"
    
    except Exception as e:
        return False, str(e)

def test_http_credentials(target, port, credentials):
    """Test HTTP basic authentication"""
    try:
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{target}:{port}"
        
        username = credentials["username"]
        password = credentials["password"]
        
        # Test common admin paths
        admin_paths = [
            "/admin/",
            "/administrator/",
            "/admin/index.php",
            "/admin/login.php",
            "/wp-admin/",
            "/wp-admin/index.php",
            "/wp-login.php",
            "/joomla/administrator/",
            "/drupal/admin/",
            "/phpmyadmin/",
            "/cpanel/",
            "/panel/",
            "/dashboard/",
            "/management/",
            "/console/",
            "/webadmin/",
            "/admincp/",
            "/admin1/",
            "/admin2/",
            "/admin-login/"
        ]
        
        for path in admin_paths:
            try:
                response = requests.get(f"{url}{path}", 
                                     auth=(username, password),
                                     headers={'User-Agent': USER_AGENT},
                                     timeout=DEFAULT_TIMEOUT,
                                     verify=False)
                
                if response.status_code == 200:
                    return True, f"HTTP login successful at {path} with {username}:{password}"
                
            except Exception:
                continue
        
        return False, "No successful HTTP login found"
    
    except Exception as e:
        return False, str(e)

def test_mysql_credentials(target, port, credentials):
    """Test MySQL credentials"""
    try:
        import mysql.connector
        
        username = credentials["username"]
        password = credentials["password"]
        
        connection = mysql.connector.connect(
            host=target,
            port=port,
            user=username,
            password=password,
            connection_timeout=5
        )
        
        connection.close()
        return True, f"MySQL login successful with {username}:{password}"
    
    except ImportError:
        return False, "MySQL connector not available"
    except Exception as e:
        return False, str(e)

def test_postgresql_credentials(target, port, credentials):
    """Test PostgreSQL credentials"""
    try:
        import psycopg2
        
        username = credentials["username"]
        password = credentials["password"]
        
        connection = psycopg2.connect(
            host=target,
            port=port,
            user=username,
            password=password,
            connect_timeout=5
        )
        
        connection.close()
        return True, f"PostgreSQL login successful with {username}:{password}"
    
    except ImportError:
        return False, "psycopg2 not available"
    except Exception as e:
        return False, str(e)

def test_redis_credentials(target, port, credentials):
    """Test Redis credentials"""
    try:
        import redis
        
        password = credentials["password"]
        
        r = redis.Redis(host=target, port=port, password=password, socket_timeout=5)
        r.ping()
        r.close()
        
        return True, f"Redis login successful with password: {password}"
    
    except ImportError:
        return False, "Redis library not available"
    except Exception as e:
        return False, str(e)

def test_mongodb_credentials(target, port, credentials):
    """Test MongoDB credentials"""
    try:
        from pymongo import MongoClient
        
        username = credentials["username"]
        password = credentials["password"]
        
        if username and password:
            uri = f"mongodb://{username}:{password}@{target}:{port}/"
        else:
            uri = f"mongodb://{target}:{port}/"
        
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        client.close()
        
        return True, f"MongoDB login successful with {username}:{password}"
    
    except ImportError:
        return False, "pymongo not available"
    except Exception as e:
        return False, str(e)

def test_service_credentials(target, port, service_type):
    """Test credentials for a specific service"""
    vulnerabilities = []
    
    # Get credentials database
    creds_db = get_default_credentials_database()
    credentials = creds_db.get(service_type, [])
    
    if not credentials:
        return vulnerabilities
    
    # Test each credential combination
    for cred in credentials[:10]:  # Limit to first 10 combinations
        try:
            if service_type == "SSH":
                success, message = test_ssh_credentials(target, port, cred)
            elif service_type == "FTP":
                success, message = test_ftp_credentials(target, port, cred)
            elif service_type == "Telnet":
                success, message = test_telnet_credentials(target, port, cred)
            elif service_type == "HTTP":
                success, message = test_http_credentials(target, port, cred)
            elif service_type == "MySQL":
                success, message = test_mysql_credentials(target, port, cred)
            elif service_type == "PostgreSQL":
                success, message = test_postgresql_credentials(target, port, cred)
            elif service_type == "Redis":
                success, message = test_redis_credentials(target, port, cred)
            elif service_type == "MongoDB":
                success, message = test_mongodb_credentials(target, port, cred)
            else:
                continue
            
            if success:
                vulnerabilities.append({
                    "service": service_type,
                    "port": port,
                    "username": cred["username"],
                    "password": cred["password"],
                    "message": message,
                    "vulnerable": True
                })
        
        except Exception as e:
            print(f"[E] Error testing {service_type} credentials: {str(e)}")
    
    return vulnerabilities

def scan_target_for_default_credentials(target):
    """Scan target for default credentials"""
    print(f"[I] Starting default credentials scan for {target}")
    
    all_vulnerabilities = []
    common_ports = get_common_service_ports()
    
    # Test each service
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_service = {}
        
        for port, service_type in common_ports.items():
            future = executor.submit(test_service_credentials, target, port, service_type)
            future_to_service[future] = (port, service_type)
        
        for future in as_completed(future_to_service):
            port, service_type = future_to_service[future]
            try:
                vulnerabilities = future.result()
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                print(f"[E] Error scanning {target}:{port} - {str(e)}")
    
    return {
        "target": target,
        "services_tested": len(common_ports),
        "vulnerabilities_found": len(all_vulnerabilities),
        "vulnerabilities": all_vulnerabilities,
        "scan_time": datetime.now().isoformat()
    }

def assess_default_credentials_risk(results):
    """Assess security risk level of default credentials findings"""
    findings = []
    severity = "I"
    
    vulnerabilities = results.get("vulnerabilities", [])
    
    if not vulnerabilities:
        return findings, severity
    
    # Count vulnerabilities by service type
    service_counts = {}
    for vuln in vulnerabilities:
        service = vuln.get("service", "Unknown")
        service_counts[service] = service_counts.get(service, 0) + 1
    
    # Critical findings - SSH, RDP, Database access
    critical_services = ["SSH", "RDP", "MySQL", "PostgreSQL", "MongoDB"]
    critical_count = sum(service_counts.get(service, 0) for service in critical_services)
    
    if critical_count > 0:
        severity = "C"
        findings.append(f"Critical default credentials: {critical_count} high-risk service access points")
        
        # List critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get("service") in critical_services]
        for vuln in critical_vulns[:3]:  # Show first 3
            service = vuln.get("service", "Unknown")
            username = vuln.get("username", "Unknown")
            password = vuln.get("password", "Unknown")
            findings.append(f"Critical: {service} access with {username}:{password}")
    
    # High findings - HTTP, FTP, Telnet
    high_services = ["HTTP", "FTP", "Telnet"]
    high_count = sum(service_counts.get(service, 0) for service in high_services)
    
    if high_count > 0:
        if severity == "I":
            severity = "H"
        findings.append(f"High-risk default credentials: {high_count} service access points")
    
    # Medium findings - Other services
    other_services = [s for s in service_counts.keys() if s not in critical_services + high_services]
    other_count = sum(service_counts.get(service, 0) for service in other_services)
    
    if other_count > 0:
        if severity == "I":
            severity = "M"
        findings.append(f"Medium-risk default credentials: {other_count} service access points")
    
    # Overall assessment
    total_vulns = len(vulnerabilities)
    if total_vulns > 5:
        if severity not in ["C", "H"]:
            severity = "H"
        findings.append(f"Multiple default credentials: {total_vulns} vulnerable access points")
    
    return findings, severity

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] Default Credentials Scanner - {target}")
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
        
        # Perform default credentials scan
        results = scan_target_for_default_credentials(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Prepare scan data for findings evaluation
        vulnerabilities = results.get("vulnerabilities", [])
        services_tested = results.get("services_tested", 0)
        
        scan_data = {
            "target": target,
            "services_tested": services_tested,
            "vulnerabilities_found": len(vulnerabilities),
            "critical_vulnerabilities": len([v for v in vulnerabilities if v.get("service") in ["SSH", "RDP", "MySQL", "PostgreSQL", "MongoDB"]]),
            "high_vulnerabilities": len([v for v in vulnerabilities if v.get("service") in ["HTTP", "FTP", "Telnet"]]),
            "vulnerabilities": vulnerabilities,
            "status": "SUCCESS" if vulnerabilities else "NO_DATA",
            "scan_completed": True
        }
        
        if vulnerabilities:
            # Assess security risk
            security_findings, severity = assess_default_credentials_risk(results)
            
            print(f"[{severity}] DEFAULT CREDENTIALS FOUND: {len(vulnerabilities)} vulnerable access points across {services_tested} services")
            
            # Display vulnerability summary
            print(f"[{severity}] Vulnerability Summary:")
            critical_count = len([v for v in vulnerabilities if v.get("service") in ["SSH", "RDP", "MySQL", "PostgreSQL", "MongoDB"]])
            high_count = len([v for v in vulnerabilities if v.get("service") in ["HTTP", "FTP", "Telnet"]])
            other_count = len(vulnerabilities) - critical_count - high_count
            
            if critical_count > 0:
                print(f"  [C] Critical: {critical_count}")
            if high_count > 0:
                print(f"  [H] High: {high_count}")
            if other_count > 0:
                print(f"  [M] Medium: {other_count}")
            print()
            
            # Display vulnerable services
            if vulnerabilities:
                print(f"[I] VULNERABLE SERVICES ({len(vulnerabilities)}):")
                for vuln in vulnerabilities[:10]:  # Show first 10
                    service = vuln.get("service", "Unknown")
                    port = vuln.get("port", "Unknown")
                    username = vuln.get("username", "Unknown")
                    password = vuln.get("password", "Unknown")
                    
                    print(f"  [{severity}] {service} ({port}/tcp) - {username}:{password}")
                
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
            print("[I] NO DATA: No default credentials found")
            security_findings = []
            severity = "I"
        
        print()
        
        # Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("default_credentials.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            if vulnerabilities:
                findings = security_findings if security_findings else [f"Found {len(vulnerabilities)} default credentials"]
            else:
                findings = ["No default credentials detected"]
            
            findings_result = {
                "success": len(vulnerabilities) > 0,
                "severity": severity,
                "findings": findings,
                "has_findings": len(vulnerabilities) > 0,
                "category": "Default Credentials Assessment"
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
            "services_tested": services_tested,
            "severity": findings_result["severity"]
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Default credentials scan stopped by user")
        return {
            "status": "INTERRUPTED",
            "execution_time": (datetime.now() - start_time).total_seconds()
        }
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        print(f"[E] FAILED: Default credentials scan error - {str(e)}")
        return {
            "status": "FAILED",
            "error": str(e),
            "execution_time": execution_time
        }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python default_credentials.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    result = main(target)
    print(json.dumps(result, indent=2)) 