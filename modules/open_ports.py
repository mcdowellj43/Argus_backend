#!/usr/bin/env python3
"""
Improved Open Ports Module - Clean Output with Success/Failure Indicators
"""

import os
import sys
import socket
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
            
            return {"port": port, "service": service}
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

def main(target, port_range="1-1000"):
    """Main execution with clean output"""
    print(f"🔍 Port Scan - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        # Clean input and resolve hostname
        host = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        try:
            ip_address = socket.gethostbyname(host)
            print(f"🎯 Target: {host} ({ip_address})")
            print(f"📡 Scanning ports: {port_range}")
            print()
        except socket.gaierror:
            print(f"❌ FAILED: Unable to resolve hostname '{host}'")
            return {"status": "FAILED", "error": "Hostname resolution failed"}
        
        # Perform port scan
        open_ports = scan_ports(host, port_range)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if open_ports:
            print(f"✅ SUCCESS: Found {len(open_ports)} open ports")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Display results
            print("🔓 Open Ports:")
            for port_info in open_ports:
                print(f"   • Port {port_info['port']} - {port_info['service']}")
            
            return {
                "status": "SUCCESS",
                "data": {"host": host, "ip": ip_address, "open_ports": open_ports},
                "count": len(open_ports),
                "execution_time": execution_time
            }
        else:
            print(f"ℹ️  NO DATA: No open ports found in range {port_range}")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {
                "status": "NO_DATA", 
                "data": {"host": host, "ip": ip_address, "port_range": port_range},
                "execution_time": execution_time
            }
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Scan stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        print(f"❌ ERROR: {str(e)}")
        print(f"⏱️  Execution time: {execution_time:.2f}s")
        return {"status": "ERROR", "error": str(e), "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        port_range = sys.argv[2] if len(sys.argv) > 2 else "1-1000"
        main(target, port_range)
    else:
        print("❌ ERROR: No target provided")
        print("Usage: python open_ports.py <target> [port_range]")
        print("Example: python open_ports.py example.com 1-1000")
        sys.exit(1)