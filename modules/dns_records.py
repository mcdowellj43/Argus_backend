#!/usr/bin/env python3
"""
Improved DNS Records Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
"""

import os
import sys
import dns.resolver
import dns.exception
from datetime import datetime

# Fix encoding issues for Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.util import clean_domain_input
    from config.settings import DEFAULT_TIMEOUT
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
    
    DEFAULT_TIMEOUT = 10

# Use our own working validation function
def validate_domain(domain):
    """Proper domain validation that actually works"""
    if not domain or len(domain) < 3 or len(domain) > 255:
        return False
    
    # Check for obvious invalid patterns
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    if domain.startswith('-') or domain.endswith('-'):
        return False
    
    # Split into parts and validate each
    parts = domain.split('.')
    if len(parts) < 2:  # Need at least domain.tld
        return False
        
    for part in parts:
        if not part or len(part) > 63:  # Each part max 63 chars
            return False
        # Each part must start/end with alphanumeric, can contain hyphens in middle
        if not part[0].isalnum() or not part[-1].isalnum():
            return False
        # Check all characters are valid
        for char in part:
            if not (char.isalnum() or char == '-'):
                return False
    
    return True

def assess_dns_security(records):
    """Assess DNS security based on available records"""
    findings = []
    severity_level = "I"  # Default to Info
    
    # Check for security-related records
    has_spf = any('spf' in txt.lower() or 'v=spf1' in txt.lower() for txt in records.get('TXT', []))
    has_dmarc = any('dmarc' in txt.lower() or 'v=dmarc1' in txt.lower() for txt in records.get('TXT', []))
    has_dkim = any('dkim' in txt.lower() for txt in records.get('TXT', []))
    
    # Security assessments
    if not has_spf:
        findings.append("No SPF record found - email spoofing possible")
        severity_level = "W"
    
    if not has_dmarc:
        findings.append("No DMARC record found - email security reduced")
        severity_level = "W"
    
    # Check for potentially sensitive information in TXT records
    for txt in records.get('TXT', []):
        if any(keyword in txt.lower() for keyword in ['password', 'key', 'secret', 'token']):
            findings.append(f"Potentially sensitive information in TXT record: {txt}")
            severity_level = "C"
    
    # Check for wildcard DNS (potential security risk)
    if any('*' in record for record in records.get('A', [])):
        findings.append("Wildcard DNS detected - potential security risk")
        severity_level = "H"
    
    return findings, severity_level

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
    print(f"[I] DNS Records Check - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        # Clean and validate input
        domain = clean_domain_input(target)
        
        if not validate_domain(domain):
            print("[E] FAILED: Invalid domain format")
            return {"status": "FAILED", "error": "Invalid domain format"}
        
        print(f"[I] Target: {domain}")
        print()
        
        # Perform DNS lookup
        dns_records = get_dns_records(domain)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if dns_records:
            total_records = sum(len(records) for records in dns_records.values())
            
            # Assess security implications
            security_findings, severity = assess_dns_security(dns_records)
            
            print(f"[S] SUCCESS: Found {total_records} DNS records")
            
            # Display security findings if any
            if security_findings:
                print(f"[{severity}] DNS Security Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display results in clean format
            for record_type, records in dns_records.items():
                print(f"[I] {record_type} Records ({len(records)}):")
                for record in records:
                    print(f"   - {record}")
                print()
            
            print(f"[I] Execution time: {execution_time:.2f}s")
            
            return {
                "status": "SUCCESS", 
                "data": dns_records,
                "count": total_records,
                "security_findings": security_findings,
                "severity": severity,
                "execution_time": execution_time
            }
        else:
            print("[I] NO DATA: No DNS records found")
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Script stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        print(f"[E] ERROR: {str(e)}")
        print(f"[I] Execution time: {execution_time:.2f}s")
        return {"status": "ERROR", "error": str(e), "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print("[E] ERROR: No target provided")
        print("Usage: python dns_records.py <domain>")
        sys.exit(1)