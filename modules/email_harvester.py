#!/usr/bin/env python3
"""
Improved Email Harvester Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
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
                         'it', 'support', 'sales', 'marketing']
    
    high_risk_found = []
    sensitive_found = []
    personal_exposed = []
    generic_exposed = []
    
    for email in emails:
        local_part = email.split('@')[0].lower()
        
        # Check for high-risk administrative emails
        if any(pattern in local_part for pattern in high_risk_patterns):
            high_risk_found.append(email)
            
        # Check for sensitive business emails
        elif any(pattern in local_part for pattern in sensitive_patterns):
            sensitive_found.append(email)
    
    # Analyze categories
    personal_exposed = categories.get("personal", [])
    generic_exposed = categories.get("generic", [])
    
    # Determine severity and findings
    if high_risk_found:
        severity = "C"
        findings.append(f"Administrative emails exposed: {len(high_risk_found)} high-value targets")
        for email in high_risk_found[:3]:  # Show first 3
            findings.append(f"Critical exposure: {email}")
    
    if sensitive_found and severity not in ["C"]:
        severity = "H"
        findings.append(f"Business-critical emails found: {len(sensitive_found)} sensitive accounts")
    
    if personal_exposed and severity not in ["C", "H"]:
        severity = "W"
        findings.append(f"Personal emails exposed: {len(personal_exposed)} individual accounts")
    
    if len(emails) >= 10 and severity == "I":
        severity = "W"
        findings.append(f"High email exposure: {len(emails)} addresses discovered")
    elif len(emails) >= 5 and severity == "I":
        findings.append(f"Moderate email exposure: {len(emails)} addresses found")
    
    # Check for potential spear-phishing targets
    if high_risk_found or sensitive_found:
        findings.append("Spear-phishing risk: High-value targets identified for social engineering")
    
    return findings, severity

def get_email_risk_level(email):
    """Determine risk level for individual email addresses"""
    local_part = email.split('@')[0].lower()
    
    # Critical patterns (administrative/executive)
    critical_patterns = ['admin', 'administrator', 'root', 'ceo', 'cto', 'cfo', 
                        'president', 'director', 'owner']
    
    # High-risk patterns (business functions)
    high_patterns = ['hr', 'finance', 'accounting', 'legal', 'security', 
                    'it', 'manager', 'supervisor']
    
    # Medium-risk patterns (support/sales)
    medium_patterns = ['support', 'sales', 'marketing', 'info', 'contact']
    
    if any(pattern in local_part for pattern in critical_patterns):
        return "C"
    elif any(pattern in local_part for pattern in high_patterns):
        return "H"
    elif any(pattern in local_part for pattern in medium_patterns):
        return "W"
    else:
        return "I"

def extract_emails_from_content(content):
    """Extract email addresses from content using regex"""
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
    personal_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                       'icloud.com', 'aol.com', 'live.com']
    
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
    """Main execution with clean output"""
    print(f"[I] Email Harvester - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("[E] FAILED: Empty target provided")
            return {"status": "FAILED", "error": "Empty target"}
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        print(f"[I] Target: {target}")
        if not BEAUTIFULSOUP_AVAILABLE:
            print("[W] BeautifulSoup not available - using basic parsing")
        print("[I] Harvesting email addresses...")
        print()
        
        # Perform email harvesting
        harvest_result = harvest_emails(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        emails = harvest_result["emails"]
        pages_checked = harvest_result["pages_checked"]
        
        if emails:
            # Categorize emails and assess security risk
            categories = categorize_emails(emails)
            security_findings, severity = assess_email_security_risk(emails, categories)
            
            print(f"[{severity}] EMAILS DISCOVERED: Found {len(emails)} email addresses")
            print(f"[I] Pages checked: {len(pages_checked)}")
            
            # Display security analysis
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display emails by risk level and category
            risk_groups = {"C": [], "H": [], "W": [], "I": []}
            for email in emails:
                risk = get_email_risk_level(email)
                risk_groups[risk].append(email)
            
            # Show critical and high-risk emails first
            for risk_level in ["C", "H", "W", "I"]:
                if risk_groups[risk_level]:
                    risk_names = {"C": "CRITICAL TARGETS", "H": "HIGH-VALUE TARGETS", 
                                 "W": "BUSINESS CONTACTS", "I": "GENERAL CONTACTS"}
                    
                    print(f"[{risk_level}] {risk_names[risk_level]} ({len(risk_groups[risk_level])}):")
                    for email in risk_groups[risk_level]:
                        print(f"  [{risk_level}] {email}")
                    print()
            
            # Show categorized view
            if categories["organizational"]:
                print(f"[I] ORGANIZATIONAL EMAILS ({len(categories['organizational'])}):")
                for email in categories["organizational"]:
                    risk = get_email_risk_level(email)
                    print(f"  [{risk}] {email}")
                print()
            
            if categories["generic"]:
                print(f"[I] GENERIC EMAILS ({len(categories['generic'])}):")
                for email in categories["generic"]:
                    print(f"  [I] {email}")
                print()
            
            if categories["personal"]:
                print(f"[W] PERSONAL EMAILS ({len(categories['personal'])}):")
                for email in categories["personal"]:
                    print(f"  [W] {email}")
                print()
            
            print("[I] PAGES SCANNED:")
            for page in pages_checked:
                print(f"  [I] {page}")
            
            print()
            print(f"[I] Execution time: {execution_time:.2f}s")
            
            return {
                "status": "SUCCESS",
                "data": {
                    "emails": emails,
                    "categories": categories,
                    "pages_checked": pages_checked
                },
                "security_findings": security_findings,
                "severity": severity,
                "count": len(emails),
                "execution_time": execution_time
            }
        else:
            print("[I] NO DATA: No email addresses found")
            print(f"[I] Pages checked: {len(pages_checked)}")
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {
                "status": "NO_DATA", 
                "data": {"pages_checked": pages_checked},
                "execution_time": execution_time
            }
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Harvesting stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
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
        return {"status": status, "error": error_msg, "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print("[E] ERROR: No target provided")
        print("Usage: python email_harvester.py <url_or_domain>")
        print("Example: python email_harvester.py example.com")
        sys.exit(1)