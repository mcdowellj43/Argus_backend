#!/usr/bin/env python3
"""
Improved Open Ports Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
"""

import os
import sys
import socket
import threading
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
    from config.settings import DEFAULT_TIMEOUT
except ImportError:
    DEFAULT_TIMEOUT = 10

def get_port_severity(port, service):
    """Assess security risk level of open ports"""
    # Critical ports (high security risk)
    critical_ports = {
        21: "FTP - Unencrypted file transfer",
        23: "Telnet - Unencrypted remote access", 
        53: "DNS - Potential information disclosure",
        135: "RPC - Windows remote procedure calls",
        139: "NetBIOS - Windows file sharing",
        445: "SMB - Windows file sharing vulnerability",
        1433: "MSSQL - Database access",
        3389: "RDP - Remote desktop access"
    }
    
    # High risk ports
    high_risk_ports = {
        22: "SSH - Remote access (secure but exposed)",
        25: "SMTP - Email server",
        110: "POP3 - Email retrieval",
        143: "IMAP - Email access",
        993: "IMAPS - Secure email access",
        995: "POP3S - Secure email retrieval"
    }
    
    # Warning ports (commonly targeted)
    warning_ports = {
        80: "HTTP - Web server (unencrypted)",
        443: "HTTPS - Web server (encrypted)",
        8080: "HTTP Alt - Alternative web server",
        8443: "HTTPS Alt - Alternative secure web server"
    }
    
    if port in critical_ports:
        return "C", critical_ports[port]
    elif port in high_risk_ports:
        return "H", high_risk_ports[port]
    elif port in warning_ports:
        return "W", warning_ports[port]
    else:
        return "I", f"{service} - Service running on port {port}"

def scan_port(host, port, timeout=1):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            
            severity, description = get_port_severity(port, service)
            return {
                "port": port, 
                "service": service,
                "severity": severity,
                "description": description
            }
    except:
        pass
    return None

def scan_ports(host, port_range="1-1000", max_workers=50):
    """Scan multiple ports with threading"""
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        ports = range(start, end + 1)
    else:
        ports = [int(port_range)]
    
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in ports}
        
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
    
    return sorted(open_ports, key=lambda x: x['port'])

def categorize_ports(open_ports):
    """Categorize ports by security risk"""
    categories = {"C": [], "H": [], "W": [], "I": []}
    
    for port_info in open_ports:
        severity = port_info["severity"]
        categories[severity].append(port_info)
    
    return categories

def main(target, port_range="1-1000"):
    """Main execution with clean output"""
    print(f"[I] Port Scan - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        # Clean input and resolve hostname
        host = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        try:
            ip_address = socket.gethostbyname(host)
            print(f"[I] Target: {host} ({ip_address})")
            print(f"[I] Scanning ports: {port_range}")
            print()
        except socket.gaierror:
            print(f"[E] FAILED: Unable to resolve hostname '{host}'")
            return {"status": "FAILED", "error": "Hostname resolution failed"}
        
        # Perform port scan
        open_ports = scan_ports(host, port_range)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if open_ports:
            # Categorize by security risk
            categories = categorize_ports(open_ports)
            
            total_ports = len(open_ports)
            critical_count = len(categories["C"])
            high_count = len(categories["H"])
            warning_count = len(categories["W"])
            info_count = len(categories["I"])
            
            print(f"[S] SUCCESS: Found {total_ports} open ports")
            print(f"[I] Security summary: {critical_count} critical, {high_count} high risk, {warning_count} warnings, {info_count} informational")
            print()
            
            # Display critical ports first
            if categories["C"]:
                print(f"[C] CRITICAL PORTS ({len(categories['C'])}):")
                for port_info in categories["C"]:
                    print(f"  [C] Port {port_info['port']} - {port_info['description']}")
                print()
            
            # Display high risk ports
            if categories["H"]:
                print(f"[H] HIGH RISK PORTS ({len(categories['H'])}):")
                for port_info in categories["H"]:
                    print(f"  [H] Port {port_info['port']} - {port_info['description']}")
                print()
            
            # Display warning ports
            if categories["W"]:
                print(f"[W] WARNING PORTS ({len(categories['W'])}):")
                for port_info in categories["W"]:
                    print(f"  [W] Port {port_info['port']} - {port_info['description']}")
                print()
            
            # Display informational ports
            if categories["I"]:
                print(f"[I] INFORMATIONAL PORTS ({len(categories['I'])}):")
                for port_info in categories["I"]:
                    print(f"  [I] Port {port_info['port']} - {port_info['service']}")
                print()
            
            print(f"[I] Execution time: {execution_time:.2f}s")
            
            return {
                "status": "SUCCESS",
                "data": {
                    "host": host, 
                    "ip": ip_address, 
                    "open_ports": open_ports,
                    "security_summary": {
                        "critical": critical_count,
                        "high": high_count, 
                        "warning": warning_count,
                        "info": info_count
                    }
                },
                "count": len(open_ports),
                "execution_time": execution_time
            }
        else:
            print(f"[I] NO DATA: No open ports found in range {port_range}")
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {
                "status": "NO_DATA", 
                "data": {"host": host, "ip": ip_address, "port_range": port_range},
                "execution_time": execution_time
            }
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Scan stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        print(f"[E] ERROR: {str(e)}")
        print(f"[I] Execution time: {execution_time:.2f}s")
        return {"status": "ERROR", "error": str(e), "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        port_range = sys.argv[2] if len(sys.argv) > 2 else "1-1000"
        main(target, port_range)
    else:
        print("[E] ERROR: No target provided")
        print("Usage: python open_ports.py <target> [port_range]")
        print("Example: python open_ports.py example.com 1-1000")
        sys.exit(1)