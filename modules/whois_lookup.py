#!/usr/bin/env python3
"""
Improved WHOIS Lookup Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
UPDATED: Integrated with centralized findings system
"""

import os
import sys
import subprocess
import re
from datetime import datetime, timedelta

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
    
    DEFAULT_TIMEOUT = 30

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

def analyze_whois_security(whois_data):
    """Analyze WHOIS data for security implications"""
    findings = []
    severity = "I"
    
    # Check domain expiration
    if 'expires' in whois_data:
        try:
            # Parse expiration date (handle various formats)
            expires_str = whois_data['expires']
            # Remove timezone info and extra text for parsing
            expires_clean = re.sub(r'[A-Z]{3}$', '', expires_str.strip())
            expires_clean = expires_clean.split('T')[0]  # Remove time part
            
            # Try different date formats
            date_formats = [
                '%Y-%m-%d',
                '%d-%m-%Y', 
                '%m/%d/%Y',
                '%Y.%m.%d',
                '%d.%m.%Y'
            ]
            
            expires_date = None
            for fmt in date_formats:
                try:
                    expires_date = datetime.strptime(expires_clean, fmt)
                    break
                except ValueError:
                    continue
            
            if expires_date:
                days_until_expiry = (expires_date - datetime.now()).days
                
                if days_until_expiry < 0:
                    findings.append("Domain has expired")
                    severity = "C"
                elif days_until_expiry <= 30:
                    findings.append(f"Domain expires in {days_until_expiry} days")
                    severity = "H"
                elif days_until_expiry <= 90:
                    findings.append(f"Domain expires in {days_until_expiry} days")
                    severity = "W"
                    
        except Exception:
            # If date parsing fails, just note it
            findings.append("Unable to parse expiration date format")
    
    # Check for privacy protection
    if 'organization' in whois_data:
        org = whois_data['organization'].lower()
        if any(privacy_keyword in org for privacy_keyword in ['privacy', 'whoisguard', 'domains by proxy']):
            findings.append("Domain uses privacy protection service")
    else:
        findings.append("Registrant information is private/redacted")
    
    # Check domain status for security issues
    if 'status' in whois_data:
        status = whois_data['status'].lower()
        if 'hold' in status:
            findings.append("Domain is on hold - may indicate issues")
            severity = "H"
        elif 'lock' in status:
            findings.append("Domain is locked (good security practice)")
        elif 'pending' in status:
            findings.append("Domain has pending status - may indicate recent changes")
            severity = "W"
    
    # Check for suspicious registrar patterns
    if 'registrar' in whois_data:
        registrar = whois_data['registrar'].lower()
        # This is a basic check - could be expanded with known problematic registrars
        if len(registrar) < 5:
            findings.append("Short registrar name - verify legitimacy")
            severity = "W"
    
    return findings, severity

def parse_whois_data(whois_output):
    """Parse WHOIS output and extract key information"""
    parsed_data = {}
    
    # Domain status
    status_patterns = [r'Domain Status:\s*(.+)', r'Status:\s*(.+)']
    for pattern in status_patterns:
        match = re.search(pattern, whois_output, re.IGNORECASE)
        if match:
            parsed_data['status'] = match.group(1).strip()
            break
    
    # Registrar
    registrar_patterns = [
        r'Registrar:\s*(.+)',
        r'Registrar Name:\s*(.+)',
        r'Sponsoring Registrar:\s*(.+)'
    ]
    for pattern in registrar_patterns:
        match = re.search(pattern, whois_output, re.IGNORECASE)
        if match:
            parsed_data['registrar'] = match.group(1).strip()
            break
    
    # Creation date
    created_patterns = [
        r'Creation Date:\s*(.+)',
        r'Created On:\s*(.+)',
        r'Registered:\s*(.+)'
    ]
    for pattern in created_patterns:
        match = re.search(pattern, whois_output, re.IGNORECASE)
        if match:
            parsed_data['created'] = match.group(1).strip()
            break
    
    # Expiration date
    expires_patterns = [
        r'Registry Expiry Date:\s*(.+)',
        r'Expiration Date:\s*(.+)',
        r'Expires On:\s*(.+)'
    ]
    for pattern in expires_patterns:
        match = re.search(pattern, whois_output, re.IGNORECASE)
        if match:
            parsed_data['expires'] = match.group(1).strip()
            break
    
    # Name servers
    ns_matches = re.findall(r'Name Server:\s*(.+)', whois_output, re.IGNORECASE)
    if ns_matches:
        parsed_data['nameservers'] = [ns.strip() for ns in ns_matches]
    
    # Organization (privacy-aware)
    org_patterns = [r'Registrant Organization:\s*(.+)', r'Organization:\s*(.+)']
    for pattern in org_patterns:
        match = re.search(pattern, whois_output, re.IGNORECASE)
        if match:
            org = match.group(1).strip()
            if org and org.lower() not in ['redacted for privacy', 'private', 'n/a']:
                parsed_data['organization'] = org
            break
    
    return parsed_data

def perform_whois_lookup(domain):
    """Perform WHOIS lookup using system command"""
    try:
        result = subprocess.run(
            ['whois', domain], 
            capture_output=True, 
            text=True, 
            timeout=DEFAULT_TIMEOUT
        )
        
        if result.returncode != 0:
            return None
        
        whois_data = result.stdout
        
        if not whois_data or len(whois_data.strip()) < 50:
            return None
        
        return parse_whois_data(whois_data)
        
    except subprocess.TimeoutExpired:
        raise Exception("WHOIS lookup timed out")
    except FileNotFoundError:
        raise Exception("WHOIS command not found. Please install whois package.")
    except Exception as e:
        raise Exception(f"WHOIS lookup failed: {str(e)}")

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] WHOIS Lookup Analysis - {target}")
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
        
        # Perform WHOIS lookup (your existing logic)
        whois_data = perform_whois_lookup(domain)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Prepare scan data for findings evaluation
        scan_data = {
            "registrar": whois_data.get("registrar") if whois_data else None,
            "organization": whois_data.get("organization") if whois_data else None,
            "expires": whois_data.get("expires") if whois_data else None,
            "created": whois_data.get("created") if whois_data else None,
            "status": whois_data.get("status") if whois_data else None,
            "nameservers": whois_data.get("nameservers", []) if whois_data else [],
            "domain": domain,
            "lookup_successful": whois_data is not None,
            "raw_data": whois_data if whois_data else {}
        }
        
        if whois_data:
            # Legacy security assessment (keep existing logic)
            security_findings, severity = analyze_whois_security(whois_data)
            
            data_fields = len([k for k, v in whois_data.items() if v])
            print(f"[S] SUCCESS: Found {data_fields} WHOIS data fields")
            
            # Display legacy security findings
            if security_findings:
                print(f"[{severity}] WHOIS Security Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display results (keep existing display)
            print("[I] WHOIS Information:")
            if 'status' in whois_data:
                print(f"  [I] Status: {whois_data['status']}")
            if 'registrar' in whois_data:
                print(f"  [I] Registrar: {whois_data['registrar']}")
            if 'created' in whois_data:
                print(f"  [I] Created: {whois_data['created']}")
            if 'expires' in whois_data:
                print(f"  [I] Expires: {whois_data['expires']}")
            if 'organization' in whois_data:
                print(f"  [I] Organization: {whois_data['organization']}")
            if 'nameservers' in whois_data:
                print(f"  [I] Name Servers ({len(whois_data['nameservers'])}):")
                for ns in whois_data['nameservers']:
                    print(f"    - {ns}")
        else:
            print("[I] NO DATA: No WHOIS information found")
            security_findings = []
            severity = "I"
        
        print()
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("whois_lookup.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            findings_result = {
                "success": whois_data is not None,
                "severity": severity,
                "findings": security_findings,
                "has_findings": len(security_findings) > 0,
                "category": "WHOIS Analysis"
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
            "security_findings": security_findings,
            "severity": findings_result["severity"],
            "count": len([k for k, v in whois_data.items() if v]) if whois_data else 0
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Lookup stopped by user")
        
        interrupt_findings = {
            "success": False,
            "severity": "I",
            "findings": ["WHOIS lookup interrupted by user"],
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
            "findings": [f"WHOIS lookup failed: {str(e)}"],
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
        print("Usage: python whois_lookup.py <domain>")
        sys.exit(1)