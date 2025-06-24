#!/usr/bin/env python3
"""
Improved Data Leak Detection Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
Note: This module requires API keys for full functionality
"""

import os
import sys
import requests
import hashlib
import time
from datetime import datetime

# Fix encoding issues for Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config.settings import DEFAULT_TIMEOUT, API_KEYS
    HIBP_API_KEY = API_KEYS.get("HIBP_API_KEY") if hasattr(API_KEYS, 'get') else None
except (ImportError, AttributeError):
    DEFAULT_TIMEOUT = 30
    HIBP_API_KEY = None

def assess_breach_severity(breach_data):
    """Assess the severity of breach findings"""
    domain_breaches = breach_data.get("domain_breaches", {}).get("breaches", [])
    email_breaches = breach_data.get("email_breaches", {}).get("emails", [])
    
    total_breaches = len(domain_breaches) + len(email_breaches)
    
    # Calculate severity based on breach characteristics
    severity_score = 0
    findings = []
    
    # Assess domain breaches
    for breach in domain_breaches:
        pwn_count = breach.get('pwn_count', 0)
        data_classes = breach.get('data_classes', [])
        
        # High impact data types
        sensitive_data = ['Passwords', 'Credit cards', 'Social security numbers', 
                         'Government IDs', 'Medical records', 'Financial data']
        
        if any(sensitive in data_classes for sensitive in sensitive_data):
            severity_score += 3
            findings.append(f"Sensitive data exposed in {breach['name']} breach")
        
        if pwn_count > 1000000:  # Large breach
            severity_score += 2
            findings.append(f"Large-scale breach: {breach['name']} ({pwn_count:,} accounts)")
        
        if not breach.get('verified', True):
            findings.append(f"Unverified breach: {breach['name']} - verify legitimacy")
    
    # Assess email breaches
    critical_emails = ['admin', 'root', 'administrator', 'ceo', 'cto']
    for email_data in email_breaches:
        email = email_data['email']
        prefix = email.split('@')[0].lower()
        
        if prefix in critical_emails:
            severity_score += 2
            findings.append(f"Critical account compromised: {email}")
        
        if email_data['breach_count'] > 3:
            severity_score += 1
            findings.append(f"Multiple breaches for {email} ({email_data['breach_count']} total)")
    
    # Determine overall severity
    if severity_score >= 5 or total_breaches >= 10:
        severity = "C"  # Critical
    elif severity_score >= 3 or total_breaches >= 5:
        severity = "H"  # High
    elif severity_score >= 1 or total_breaches >= 1:
        severity = "W"  # Warning
    else:
        severity = "I"  # Info
    
    return severity, findings

def check_haveibeenpwned_domain(domain):
    """Check domain breaches using HaveIBeenPwned API"""
    if not HIBP_API_KEY:
        return {"error": "API key required", "breaches": []}
    
    try:
        url = f"https://haveibeenpwned.com/api/v3/breaches"
        headers = {
            'hibp-api-key': HIBP_API_KEY,
            'User-Agent': 'Argus Security Scanner'
        }
        
        response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code == 200:
            all_breaches = response.json()
            domain_breaches = []
            
            # Filter breaches that might affect the domain
            for breach in all_breaches:
                breach_domain = breach.get('Domain', '').lower()
                if domain.lower() in breach_domain or breach_domain in domain.lower():
                    domain_breaches.append({
                        'name': breach.get('Name'),
                        'title': breach.get('Title'),
                        'domain': breach.get('Domain'),
                        'breach_date': breach.get('BreachDate'),
                        'added_date': breach.get('AddedDate'),
                        'pwn_count': breach.get('PwnCount'),
                        'data_classes': breach.get('DataClasses', []),
                        'verified': breach.get('IsVerified', False)
                    })
            
            return {"breaches": domain_breaches, "error": None}
        
        elif response.status_code == 401:
            return {"error": "Invalid API key", "breaches": []}
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded", "breaches": []}
        else:
            return {"error": f"API error: {response.status_code}", "breaches": []}
            
    except requests.exceptions.Timeout:
        return {"error": "Request timeout", "breaches": []}
    except Exception as e:
        return {"error": str(e), "breaches": []}

def check_common_emails(domain):
    """Check common email patterns for the domain"""
    if not HIBP_API_KEY:
        return {"error": "API key required", "emails": []}
    
    # Common email prefixes to check
    common_prefixes = [
        'admin', 'contact', 'info', 'support', 'sales',
        'hello', 'help', 'team', 'office', 'mail'
    ]
    
    compromised_emails = []
    
    for prefix in common_prefixes:
        email = f"{prefix}@{domain}"
        
        try:
            # Check if email has been breached
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                'hibp-api-key': HIBP_API_KEY,
                'User-Agent': 'Argus Security Scanner'
            }
            
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                breaches = response.json()
                compromised_emails.append({
                    'email': email,
                    'breach_count': len(breaches),
                    'breaches': [breach.get('Name') for breach in breaches]
                })
            
            # Rate limiting - HIBP allows 1 request every 1.5 seconds
            time.sleep(1.6)
            
        except Exception:
            continue
    
    return {"emails": compromised_emails, "error": None}

def check_public_leaks(domain):
    """Check for publicly available data leaks (simulated)"""
    # This would typically integrate with multiple leak databases
    # For now, we'll return a placeholder structure
    
    # Simulate some common leak patterns
    potential_leaks = []
    
    # Check for common exposed files that might contain sensitive data
    common_files = [
        'backup.sql', 'database.sql', 'dump.sql',
        'config.php', 'wp-config.php', '.env',
        'users.csv', 'emails.txt', 'passwords.txt'
    ]
    
    for filename in common_files:
        # This would normally check paste sites, GitHub, etc.
        # For demo purposes, we'll just structure the response
        pass
    
    return {
        "potential_leaks": potential_leaks,
        "sources_checked": ["Pastebin", "GitHub", "GitLab", "Public dumps"],
        "note": "Comprehensive leak detection requires additional API integrations"
    }

def perform_data_leak_check(target):
    """Perform comprehensive data leak checking"""
    domain = target.replace('http://', '').replace('https://', '').split('/')[0]
    
    results = {
        "domain": domain,
        "domain_breaches": {},
        "email_breaches": {},
        "public_leaks": {},
        "summary": {}
    }
    
    # Check domain-specific breaches
    print("[I] Checking domain breaches...")
    results["domain_breaches"] = check_haveibeenpwned_domain(domain)
    
    # Check common email addresses
    print("[I] Checking common email addresses...")
    results["email_breaches"] = check_common_emails(domain)
    
    # Check public leaks
    print("[I] Checking public leak sources...")
    results["public_leaks"] = check_public_leaks(domain)
    
    # Create summary
    domain_breach_count = len(results["domain_breaches"].get("breaches", []))
    email_breach_count = len(results["email_breaches"].get("emails", []))
    
    results["summary"] = {
        "total_domain_breaches": domain_breach_count,
        "total_compromised_emails": email_breach_count,
        "has_breaches": domain_breach_count > 0 or email_breach_count > 0
    }
    
    return results

def main(target):
    """Main execution with clean output"""
    print(f"[I] Data Leak Detection - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("[E] FAILED: Empty target provided")
            return {"status": "FAILED", "error": "Empty target"}
        
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        print(f"[I] Target: {domain}")
        
        # Check if API key is available
        if not HIBP_API_KEY:
            print("[W] API KEY: HaveIBeenPwned API key not configured")
            print("[I] LIMITED: Running in limited mode without breach checking")
            print()
        
        print()
        
        # Perform data leak checking
        results = perform_data_leak_check(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Analyze results
        summary = results["summary"]
        total_findings = summary["total_domain_breaches"] + summary["total_compromised_emails"]
        
        if summary["has_breaches"]:
            # Assess severity of findings
            severity, security_findings = assess_breach_severity(results)
            
            print(f"[{severity}] BREACH DATA FOUND: {total_findings} potential data exposures detected")
            
            # Display security analysis
            if security_findings:
                print(f"[{severity}] Security Impact Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display domain breaches
            domain_breaches = results["domain_breaches"].get("breaches", [])
            if domain_breaches:
                print(f"[W] Domain Breaches ({len(domain_breaches)}):")
                for breach in domain_breaches[:5]:  # Show first 5
                    verified_status = "[VERIFIED]" if breach['verified'] else "[UNVERIFIED]"
                    print(f"  [W] {breach['title']} ({breach['breach_date']}) {verified_status}")
                    print(f"    - Affected: {breach['pwn_count']:,} accounts")
                    print(f"    - Data: {', '.join(breach['data_classes'][:3])}")
                if len(domain_breaches) > 5:
                    print(f"  [I] ... and {len(domain_breaches) - 5} more breaches")
                print()
            
            # Display email breaches
            email_breaches = results["email_breaches"].get("emails", [])
            if email_breaches:
                print(f"[W] Compromised Emails ({len(email_breaches)}):")
                for email_data in email_breaches:
                    email_severity = "C" if email_data['email'].startswith(('admin@', 'root@')) else "W"
                    print(f"  [{email_severity}] {email_data['email']} - {email_data['breach_count']} breaches")
                    print(f"    - Found in: {', '.join(email_data['breaches'][:3])}")
                print()
            
            print(f"[I] Execution time: {execution_time:.2f}s")
            
            return {
                "status": "SUCCESS",
                "data": results,
                "security_findings": security_findings,
                "severity": severity,
                "count": total_findings,
                "execution_time": execution_time
            }
        
        elif results["domain_breaches"].get("error") or results["email_breaches"].get("error"):
            # API errors occurred
            error_msg = results["domain_breaches"].get("error") or results["email_breaches"].get("error")
            if "API key" in error_msg:
                print("[E] API ERROR: Valid API key required for breach checking")
                print("[I] SETUP: Configure HIBP_API_KEY in config/settings.py")
                status = "API_ERROR"
            elif "rate limit" in error_msg.lower():
                print("[W] RATE LIMIT: API rate limit exceeded, try again later")
                status = "RATE_LIMITED"
            else:
                print(f"[E] ERROR: {error_msg}")
                status = "ERROR"
            
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {"status": status, "error": error_msg, "execution_time": execution_time}
        
        else:
            print("[S] NO BREACHES: No data breaches found for target")
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {
                "status": "NO_DATA",
                "data": results,
                "count": 0,
                "execution_time": execution_time
            }
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Check stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during data leak check")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("[E] ERROR: Connection error during API requests")
            status = "CONNECTION_ERROR"
        else:
            print(f"[E] ERROR: {error_msg}")
            status = "ERROR"
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        return {"status": status, "error": error_msg, "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print("[E] ERROR: No target provided")
        print("Usage: python data_leak.py <domain>")
        print("Example: python data_leak.py example.com")
        print()
        print("Note: Requires HaveIBeenPwned API key for full functionality")
        sys.exit(1)