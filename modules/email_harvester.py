#!/usr/bin/env python3
"""
Improved Email Harvester Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
UPDATED: Integrated with centralized findings system
"""

import os
import sys
import requests
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

# Fix encoding issues for Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

# Try to import BeautifulSoup with fallback
try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

def assess_email_security_risk(emails, categories):
    """Assess security risk of harvested emails"""
    findings = []
    severity = "I"
    
    if not emails:
        return findings, severity
    
    # High-risk email patterns (admin, executive accounts)
    high_risk_patterns = ['admin', 'administrator', 'root', 'ceo', 'cto', 'cfo', 
                         'president', 'director', 'manager', 'owner']
    
    # Sensitive business patterns
    sensitive_patterns = ['hr', 'finance', 'accounting', 'legal', 'security',
                         'support', 'billing', 'sales']
    
    high_risk_emails = []
    sensitive_emails = []
    
    for email in emails:
        local_part = email.split('@')[0].lower()
        
        # Check for high-risk patterns
        if any(pattern in local_part for pattern in high_risk_patterns):
            high_risk_emails.append(email)
        
        # Check for sensitive business patterns
        elif any(pattern in local_part for pattern in sensitive_patterns):
            sensitive_emails.append(email)
    
    # Analyze findings based on categories and patterns
    if high_risk_emails:
        findings.append(f"Executive/administrative emails discovered: {len(high_risk_emails)}")
        severity = "H"
    
    if sensitive_emails:
        findings.append(f"Business function emails found: {len(sensitive_emails)}")
        if severity == "I":
            severity = "W"
    
    if len(emails) > 10:
        findings.append(f"Large email exposure: {len(emails)} addresses harvested")
        if severity == "I":
            severity = "W"
    
    # Check for personal vs organizational emails
    org_emails = len(categories.get("organizational", []))
    personal_emails = len(categories.get("personal", []))
    
    if personal_emails > 0:
        findings.append(f"Personal email addresses found: {personal_emails}")
    
    if org_emails > 5:
        findings.append(f"Extensive organizational email exposure: {org_emails}")
        if severity == "I":
            severity = "W"
    
    # Generic contact emails are usually acceptable
    generic_emails = len(categories.get("generic", []))
    if generic_emails > 0 and len(findings) == 0:
        findings.append(f"Generic contact emails found: {generic_emails}")
    
    return findings, severity

def extract_emails_from_content(content):
    """Extract email addresses from content using regex"""
    # Improved email regex pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = set(re.findall(email_pattern, content, re.IGNORECASE))
    
    # Filter out common false positives
    filtered_emails = set()
    for email in emails:
        email = email.lower()
        # Skip obvious false positives
        if not any(skip in email for skip in [
            'example.com', 'test.com', 'placeholder', 'dummy',
            'noreply@', 'no-reply@', '.png', '.jpg', '.gif', '.svg'
        ]):
            filtered_emails.add(email)
    
    return filtered_emails

def get_page_content(url, session, timeout=10):
    """Get content from a single page"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = session.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return None

def find_contact_pages_regex(base_url, content):
    """Find contact pages using regex (fallback when BeautifulSoup unavailable)"""
    contact_urls = []
    
    try:
        # Simple regex to find contact-related links
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>'
        matches = re.findall(link_pattern, content, re.IGNORECASE)
        
        contact_keywords = ['contact', 'about', 'team', 'staff']
        
        for href, link_text in matches:
            if any(keyword in href.lower() or keyword in link_text.lower() 
                   for keyword in contact_keywords):
                full_url = urljoin(base_url, href)
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    contact_urls.append(full_url)
                    
    except Exception:
        pass
    
    return contact_urls[:3]

def find_contact_pages(base_url, content):
    """Find potential contact pages from main page"""
    if not BEAUTIFULSOUP_AVAILABLE:
        return find_contact_pages_regex(base_url, content)
    
    contact_urls = []
    
    try:
        soup = BeautifulSoup(content, 'html.parser')
        contact_keywords = ['contact', 'about', 'team', 'staff']
        
        for link in soup.find_all('a', href=True):
            href = link['href'].lower()
            link_text = link.get_text(strip=True).lower()
            
            if any(keyword in href or keyword in link_text for keyword in contact_keywords):
                full_url = urljoin(base_url, link['href'])
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    contact_urls.append(full_url)
    except:
        pass
    
    return contact_urls[:3]  # Limit to 3 contact pages

def harvest_emails(target):
    """Harvest email addresses from target website"""
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    all_emails = set()
    pages_checked = []
    
    with requests.Session() as session:
        # Get main page content
        main_content = get_page_content(target, session)
        if main_content:
            pages_checked.append(target)
            emails = extract_emails_from_content(main_content)
            all_emails.update(emails)
            
            # Check contact pages
            contact_pages = find_contact_pages(target, main_content)
            for contact_url in contact_pages:
                contact_content = get_page_content(contact_url, session)
                if contact_content:
                    pages_checked.append(contact_url)
                    contact_emails = extract_emails_from_content(contact_content)
                    all_emails.update(contact_emails)
    
    return {
        "emails": sorted(list(all_emails)),
        "pages_checked": pages_checked
    }

def categorize_emails(emails):
    """Categorize emails by domain type and risk level"""
    categories = {
        "organizational": [],
        "personal": [],
        "generic": []
    }
    
    generic_prefixes = ['info', 'contact', 'support', 'admin', 'hello', 'mail']
    personal_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 
                       'outlook.com', 'icloud.com', 'aol.com', 'live.com']
    
    for email in emails:
        local, domain = email.split('@', 1)
        
        if any(prefix in local.lower() for prefix in generic_prefixes):
            categories["generic"].append(email)
        elif domain.lower() in personal_domains:
            categories["personal"].append(email)
        else:
            categories["organizational"].append(email)
    
    return categories

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] Email Harvester Analysis - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("[E] FAILED: Empty target provided")
            
            # Error findings for empty target
            error_findings = {
                "success": False,
                "severity": "I",
                "findings": ["Empty target provided"],
                "has_findings": True,
                "category": "Input Error"
            }
            
            return {
                "status": "FAILED", 
                "error": "Empty target",
                "findings": error_findings,
                "execution_time": (datetime.now() - start_time).total_seconds()
            }
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        print(f"[I] Target: {target}")
        if not BEAUTIFULSOUP_AVAILABLE:
            print("[W] BeautifulSoup not available - using basic parsing")
        print("[I] Harvesting email addresses...")
        print()
        
        # Perform email harvesting (your existing logic)
        harvest_result = harvest_emails(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        emails = harvest_result["emails"]
        pages_checked = harvest_result["pages_checked"]
        
        # Prepare scan data for findings evaluation
        scan_data = {
            "emails": emails,
            "total_emails": len(emails),
            "pages_checked": pages_checked,
            "pages_scanned": len(pages_checked),
            "status": "SUCCESS" if emails else "NO_DATA",
            "target": target
        }
        
        if emails:
            # Categorize emails and assess security risk (keep existing logic)
            categories = categorize_emails(emails)
            security_findings, severity = assess_email_security_risk(emails, categories)
            
            print(f"[{severity}] EMAILS DISCOVERED: Found {len(emails)} email addresses")
            print(f"[I] Pages checked: {len(pages_checked)}")
            
            # Display legacy security analysis
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display results by category (keep existing display)
            for category, email_list in categories.items():
                if email_list:
                    print(f"[I] {category.title()} Emails ({len(email_list)}):")
                    for email in email_list[:5]:  # Show first 5
                        print(f"   - {email}")
                    if len(email_list) > 5:
                        print(f"   - ... and {len(email_list) - 5} more")
                    print()
        else:
            print("[I] NO DATA: No email addresses found")
            print(f"[I] Pages checked: {len(pages_checked)}")
            security_findings = []
            severity = "I"
            categories = {"organizational": [], "personal": [], "generic": []}
        
        print()
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("email_harvester.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            findings_result = {
                "success": len(emails) > 0,
                "severity": severity,
                "findings": security_findings,
                "has_findings": len(security_findings) > 0,
                "category": "Email Discovery"
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
            "security_findings": security_findings,
            "severity": findings_result["severity"],
            "count": len(emails),
            "categories": categories
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Harvesting stopped by user")
        
        interrupt_findings = {
            "success": False,
            "severity": "I",
            "findings": ["Email harvesting interrupted by user"],
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
        error_msg = str(e)
        
        # Classify error types (keep existing logic)
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during email harvesting")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("[E] ERROR: Connection error - target may be unreachable")
            status = "CONNECTION_ERROR"
        else:
            print(f"[E] ERROR: {error_msg}")
            status = "ERROR"
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        
        # Error findings
        error_findings = {
            "success": False,
            "severity": "I",
            "findings": [f"Email harvesting failed: {error_msg}"],
            "has_findings": True,
            "category": "Error"
        }
        
        return {
            "status": status,
            "error": error_msg,
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
        print("Usage: python email_harvester.py <url_or_domain>")
        print("Example: python email_harvester.py example.com")
        sys.exit(1)