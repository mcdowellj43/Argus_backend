#!/usr/bin/env python3
"""
Improved Email Harvester Module - Clean Output with Success/Failure Indicators
"""

import os
import sys
import requests
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import USER_AGENT, DEFAULT_TIMEOUT

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

def find_contact_pages(base_url, content):
    """Find potential contact pages from main page"""
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
    """Categorize emails by domain type"""
    categories = {
        "organizational": [],
        "personal": [],
        "generic": []
    }
    
    generic_prefixes = ['info', 'contact', 'support', 'admin', 'hello', 'mail']
    personal_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    
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
    print(f"🔍 Email Harvester - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("❌ FAILED: Empty target provided")
            return {"status": "FAILED", "error": "Empty target"}
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        print(f"🎯 Target: {target}")
        print("📧 Harvesting email addresses...")
        print()
        
        # Perform email harvesting
        harvest_result = harvest_emails(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        emails = harvest_result["emails"]
        pages_checked = harvest_result["pages_checked"]
        
        if emails:
            print(f"✅ SUCCESS: Found {len(emails)} email addresses")
            print(f"📄 Pages checked: {len(pages_checked)}")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Categorize and display emails
            categories = categorize_emails(emails)
            
            if categories["organizational"]:
                print(f"🏢 Organizational Emails ({len(categories['organizational'])}):")
                for email in categories["organizational"]:
                    print(f"   • {email}")
                print()
            
            if categories["generic"]:
                print(f"📬 Generic Emails ({len(categories['generic'])}):")
                for email in categories["generic"]:
                    print(f"   • {email}")
                print()
            
            if categories["personal"]:
                print(f"👤 Personal Emails ({len(categories['personal'])}):")
                for email in categories["personal"]:
                    print(f"   • {email}")
                print()
            
            print("📄 Pages Scanned:")
            for page in pages_checked:
                print(f"   • {page}")
            
            return {
                "status": "SUCCESS",
                "data": {
                    "emails": emails,
                    "categories": categories,
                    "pages_checked": pages_checked
                },
                "count": len(emails),
                "execution_time": execution_time
            }
        else:
            print("ℹ️  NO DATA: No email addresses found")
            print(f"📄 Pages checked: {len(pages_checked)}")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {
                "status": "NO_DATA", 
                "data": {"pages_checked": pages_checked},
                "execution_time": execution_time
            }
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Harvesting stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("⏰ TIMEOUT: Request timeout during email harvesting")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("🌐 ERROR: Connection error - target may be unreachable")
            status = "CONNECTION_ERROR"
        else:
            print(f"❌ ERROR: {error_msg}")
            status = "ERROR"
        
        print(f"⏱️  Execution time: {execution_time:.2f}s")
        return {"status": status, "error": error_msg, "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print("❌ ERROR: No target provided")
        print("Usage: python email_harvester.py <url_or_domain>")
        print("Example: python email_harvester.py example.com")
        sys.exit(1)