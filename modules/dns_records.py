# modules/dns_records.py - Updated with findings integration
#!/usr/bin/env python3

import os
import sys
import dns.resolver
from datetime import datetime

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import your existing settings
try:
    from config.settings import USER_AGENT, DEFAULT_TIMEOUT
except ImportError:
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    DEFAULT_TIMEOUT = 10

# NEW: Import findings system
try:
    from config.findings_rules import evaluate_findings, display_findings_result
    FINDINGS_AVAILABLE = True
except ImportError:
    print("[W] Findings system not available - running in legacy mode")
    FINDINGS_AVAILABLE = False

def perform_dns_enumeration(domain):
    """
    Perform DNS record enumeration
    (Your existing DNS enumeration logic goes here)
    """
    records = []
    
    # Common record types to check
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                records.append({
                    "type": record_type,
                    "name": domain,
                    "value": str(rdata),
                    "ttl": answers.ttl
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            continue
        except Exception:
            continue
    
    return {
        "records": records,
        "total_records": len(records),
        "status": "SUCCESS" if records else "FAILED",
        "domain": domain
    }

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] DNS Records Analysis - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        # Clean and validate input
        domain = target.strip().lower()
        if domain.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
        
        print(f"[I] Target: {domain}")
        print("[I] Enumerating DNS records...")
        print()
        
        # Perform DNS enumeration (your existing logic)
        scan_data = perform_dns_enumeration(domain)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Traditional output first
        if scan_data["records"]:
            print(f"[S] SUCCESS: Found {len(scan_data['records'])} DNS records")
            
            # Show record types found
            record_types = list(set(r["type"] for r in scan_data["records"]))
            print(f"[I] Record types: {', '.join(record_types)}")
            
            # Show some sample records
            for record in scan_data["records"][:5]:  # Show first 5
                print(f"[I] {record['type']}: {record['value']}")
            
            if len(scan_data["records"]) > 5:
                print(f"[I] ... and {len(scan_data['records']) - 5} more records")
        else:
            print("[E] FAILED: No DNS records found")
        
        print()
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("dns_records.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            findings_result = {
                "success": scan_data["status"] == "SUCCESS",
                "severity": "I",
                "findings": [],
                "has_findings": False
            }
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        print()
        
        # Return standardized format
        return {
            "status": "SUCCESS" if findings_result["success"] else "FAILED",
            "data": scan_data,
            "findings": findings_result,
            "execution_time": execution_time,
            "target": domain
        }
        
    except Exception as e:
        print(f"[E] FAILED: {str(e)}")
        
        # Error findings
        error_findings = {
            "success": False,
            "severity": "I",
            "findings": [f"DNS enumeration failed: {str(e)}"],
            "has_findings": True,
            "category": "Error"
        }
        
        return {
            "status": "FAILED",
            "error": str(e),
            "findings": error_findings,
            "execution_time": (datetime.now() - start_time).total_seconds()
        }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python dns_records.py <domain>")
        sys.exit(1)
    
    target = sys.argv[1]
    result = main(target)
    
    # Exit with appropriate code
    sys.exit(0 if result["status"] == "SUCCESS" else 1)