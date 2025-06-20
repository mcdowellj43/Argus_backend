#!/usr/bin/env python3
"""
Improved DNS Records Module - Clean Output with Success/Failure Indicators
"""

import os
import sys
import dns.resolver
import dns.exception
from datetime import datetime

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain

def get_dns_records(domain):
    """Get DNS records for domain with error handling"""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=10)
            records[record_type] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException:
            continue
    
    return records

def main(target):
    """Main execution with clean output"""
    print(f"🔍 DNS Records Check - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        # Clean and validate input
        domain = clean_domain_input(target)
        
        if not validate_domain(domain):
            print("❌ FAILED: Invalid domain format")
            return {"status": "FAILED", "error": "Invalid domain format"}
        
        # Perform DNS lookup
        dns_records = get_dns_records(domain)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if dns_records:
            total_records = sum(len(records) for records in dns_records.values())
            print(f"✅ SUCCESS: Found {total_records} DNS records")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Display results in clean format
            for record_type, records in dns_records.items():
                print(f"📋 {record_type} Records ({len(records)}):")
                for record in records:
                    print(f"   • {record}")
                print()
            
            return {
                "status": "SUCCESS", 
                "data": dns_records,
                "count": total_records,
                "execution_time": execution_time
            }
        else:
            print("ℹ️  NO DATA: No DNS records found")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Script stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        print(f"❌ ERROR: {str(e)}")
        print(f"⏱️  Execution time: {execution_time:.2f}s")
        return {"status": "ERROR", "error": str(e), "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print("❌ ERROR: No target provided")
        print("Usage: python dns_records.py <domain>")
        sys.exit(1)