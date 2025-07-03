#!/usr/bin/env python3
"""
Improved DNS Records Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
UPDATED: Integrated with centralized findings system
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

# NEW: Import findings system
try:
    from config.findings_rules import evaluate_findings, display_findings_result
    FINDINGS_AVAILABLE = True
except ImportError:
    print("[W] Findings system not available - running in legacy mode")
    FINDINGS_AVAILABLE = False

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
    if len(parts) < 2:
        return False
    
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not part.replace('-', '').isalnum():
            return False
    
    return True

def assess_dns_security(dns_records):
    """Assess security implications of DNS configuration"""
    findings = []
    severity_level = "I"
    
    # Check for multiple A records (potential load balancing or CDN)
    if 'A' in dns_records and len(dns_records['A']) > 3:
        findings.append("Multiple A records detected - load balancing configuration")
        severity_level = "W"
    
    # Check for TXT records that might contain sensitive info
    if 'TXT' in dns_records:
        for txt in dns_records['TXT']:
            if any(keyword in txt.lower() for keyword in ['spf', 'dmarc', 'dkim']):
                findings.append("Email security records found")
            if 'verification' in txt.lower() or 'token' in txt.lower():
                findings.append("Domain verification tokens detected")
                severity_level = "W"
    
    # Check for CNAME records pointing to external services
    if 'CNAME' in dns_records:
        for cname in dns_records['CNAME']:
            if any(service in cname.lower() for service in ['aws', 'azure', 'cloudfront', 'cdn']):
                findings.append("External cloud services detected via CNAME")
    
    # Check for wildcard DNS (less common in basic queries but possible)
    if any('*' in str(record) for records in dns_records.values() for record in records):
        findings.append("Wildcard DNS detected - potential security risk")
        severity_level = "H"
    
    return findings, severity_level

def get_dns_records(domain):
    """Get DNS records for domain with error handling"""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=DEFAULT_TIMEOUT)
            records[record_type] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException:
            continue
    
    return records

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] DNS Records Analysis - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        # Clean and validate input
        domain = clean_domain_input(target)
        
        if not validate_domain(domain):
            print("[E] FAILED: Invalid domain format")
            
            # Error findings for invalid input
            error_findings = {
                "success": False,
                "severity": "I",
                "findings": ["Invalid domain format provided"],
                "has_findings": True,
                "category": "Input Error"
            }
            
            return {
                "status": "FAILED", 
                "error": "Invalid domain format",
                "findings": error_findings,
                "execution_time": (datetime.now() - start_time).total_seconds()
            }
        
        print(f"[I] Target: {domain}")
        print()
        
        # Perform DNS lookup (your existing logic)
        dns_records = get_dns_records(domain)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Prepare scan data for findings evaluation
        all_records = []
        for record_type, records in dns_records.items():
            for record_value in records:
                all_records.append({
                    "type": record_type,
                    "name": domain,
                    "value": record_value
                })
        
        scan_data = {
            "records": all_records,
            "total_records": len(all_records),
            "status": "SUCCESS" if dns_records else "FAILED",
            "domain": domain,
            "raw_records": dns_records  # Keep original format for display
        }
        
        if dns_records:
            total_records = sum(len(records) for records in dns_records.values())
            
            # Legacy security assessment (keep existing logic)
            security_findings, severity = assess_dns_security(dns_records)
            
            print(f"[S] SUCCESS: Found {total_records} DNS records")
            
            # Display legacy security findings if any
            if security_findings:
                print(f"[{severity}] DNS Security Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display results in clean format (keep existing display)
            for record_type, records in dns_records.items():
                print(f"[I] {record_type} Records ({len(records)}):")
                for record in records:
                    print(f"   - {record}")
                print()
        else:
            print("[I] NO DATA: No DNS records found")
        
        print()
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("dns_records.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            findings_result = {
                "success": scan_data["status"] == "SUCCESS",
                "severity": severity if dns_records else "I",
                "findings": security_findings if dns_records else [],
                "has_findings": len(security_findings) > 0 if dns_records else False,
                "category": "DNS Analysis"
            }
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        print()
        
        # Return standardized format
        return {
            "status": "SUCCESS" if findings_result["success"] else "FAILED",
            "data": scan_data,
            "findings": findings_result,
            "execution_time": execution_time,
            "target": domain,
            # Keep legacy fields for backward compatibility
            "count": scan_data["total_records"],
            "security_findings": security_findings if dns_records else [],
            "severity": findings_result["severity"]
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Script stopped by user")
        
        interrupt_findings = {
            "success": False,
            "severity": "I",
            "findings": ["Script interrupted by user"],
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
        print(f"[E] ERROR: {str(e)}")
        print(f"[I] Execution time: {execution_time:.2f}s")
        
        # Error findings
        error_findings = {
            "success": False,
            "severity": "I",
            "findings": [f"DNS enumeration failed: {str(e)}"],
            "has_findings": True,
            "category": "Error"
        }
        
        return {
            "status": "ERROR",
            "error": str(e),
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
        print("Usage: python dns_records.py <domain>")
        sys.exit(1)