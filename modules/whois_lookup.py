#!/usr/bin/env python3
"""
Improved WHOIS Lookup Module - Clean Output with Success/Failure Indicators
"""

import os
import sys
import subprocess
import re
from datetime import datetime

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain

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
            timeout=30
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
    """Main execution with clean output"""
    print(f"🔍 WHOIS Lookup - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        # Clean and validate input
        domain = clean_domain_input(target)
        
        if not validate_domain(domain):
            print("❌ FAILED: Invalid domain format")
            return {"status": "FAILED", "error": "Invalid domain format"}
        
        print(f"🎯 Target: {domain}")
        print()
        
        # Perform WHOIS lookup
        whois_data = perform_whois_lookup(domain)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if whois_data:
            data_fields = len([k for k, v in whois_data.items() if v])
            print(f"✅ SUCCESS: Found {data_fields} WHOIS data fields")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Display results
            print("📋 WHOIS Information:")
            if 'status' in whois_data:
                print(f"   • Status: {whois_data['status']}")
            if 'registrar' in whois_data:
                print(f"   • Registrar: {whois_data['registrar']}")
            if 'created' in whois_data:
                print(f"   • Created: {whois_data['created']}")
            if 'expires' in whois_data:
                print(f"   • Expires: {whois_data['expires']}")
            if 'organization' in whois_data:
                print(f"   • Organization: {whois_data['organization']}")
            if 'nameservers' in whois_data:
                print(f"   • Name Servers ({len(whois_data['nameservers'])}):")
                for ns in whois_data['nameservers']:
                    print(f"     - {ns}")
            
            return {
                "status": "SUCCESS",
                "data": whois_data,
                "count": data_fields,
                "execution_time": execution_time
            }
        else:
            print("ℹ️  NO DATA: No WHOIS information found")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Lookup stopped by user")
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
        print("Usage: python whois_lookup.py <domain>")
        sys.exit(1)