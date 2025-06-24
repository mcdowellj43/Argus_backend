#!/usr/bin/env python3
"""
Improved Social Media Module - Clean Output with Success/Failure Indicators
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

def assess_social_media_security_risk(profiles, platform_groups):
    """Assess security risk of discovered social media profiles"""
    findings = []
    severity = "I"
    
    if not profiles:
        return findings, severity
    
    # High-risk platforms (often targeted for social engineering)
    high_risk_platforms = ['LinkedIn', 'Twitter', 'X (Twitter)', 'Facebook']
    
    # Professional/business platforms
    business_platforms = ['LinkedIn', 'GitHub']
    
    # Social platforms (personal information exposure)
    social_platforms = ['Facebook', 'Instagram', 'TikTok', 'Snapchat']
    
    high_risk_found = []
    business_found = []
    social_found = []
    
    for platform in platform_groups.keys():
        if platform in high_risk_platforms:
            high_risk_found.append(platform)
        if platform in business_platforms:
            business_found.append(platform)
        if platform in social_platforms:
            social_found.append(platform)
    
    # Determine severity and findings
    if len(profiles) >= 8:
        severity = "H"
        findings.append(f"High social media exposure: {len(profiles)} profiles across {len(platform_groups)} platforms")
    elif len(profiles) >= 5:
        severity = "W"
        findings.append(f"Moderate social media presence: {len(profiles)} profiles discovered")
    
    if high_risk_found:
        if severity not in ["H"]:
            severity = "W"
        findings.append(f"High-risk platforms identified: {', '.join(high_risk_found)} (social engineering targets)")
    
    if business_found:
        findings.append(f"Professional platforms found: {', '.join(business_found)} (business intelligence risk)")
    
    if social_found:
        findings.append(f"Personal platforms discovered: {', '.join(social_found)} (privacy exposure risk)")
    
    # OSINT and social engineering risks
    if len(platform_groups) >= 4:
        findings.append("OSINT risk: Multiple platforms enable comprehensive profile building")
    
    if 'LinkedIn' in platform_groups and ('Facebook' in platform_groups or 'Instagram' in platform_groups):
        findings.append("Cross-platform correlation risk: Professional and personal profiles linked")
    
    return findings, severity

def get_platform_risk_level(platform):
    """Determine risk level for individual platforms"""
    high_risk_platforms = ['LinkedIn', 'Twitter', 'X (Twitter)', 'Facebook']
    medium_risk_platforms = ['Instagram', 'GitHub', 'YouTube']
    
    if platform in high_risk_platforms:
        return "H"
    elif platform in medium_risk_platforms:
        return "W"
    else:
        return "I"

def get_social_platforms():
    """Define social media platforms to search for"""
    return {
        'facebook.com': 'Facebook',
        'twitter.com': 'Twitter',
        'x.com': 'X (Twitter)',
        'linkedin.com': 'LinkedIn',
        'instagram.com': 'Instagram',
        'youtube.com': 'YouTube',
        'github.com': 'GitHub',
        'pinterest.com': 'Pinterest',
        'tiktok.com': 'TikTok',
        'snapchat.com': 'Snapchat',
        'reddit.com': 'Reddit',
        'discord.com': 'Discord',
        'telegram.org': 'Telegram',
        'whatsapp.com': 'WhatsApp'
    }

def extract_social_links_regex(content, base_url):
    """Extract social media links using regex (fallback when BeautifulSoup unavailable)"""
    social_platforms = get_social_platforms()
    found_profiles = []
    
    try:
        # Simple regex to find links
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>'
        matches = re.findall(link_pattern, content, re.IGNORECASE)
        
        for href, link_text in matches:
            # Convert relative URLs to absolute
            if href.startswith('/'):
                href = urljoin(base_url, href)
            
            # Check if link contains social media domain
            for domain, platform in social_platforms.items():
                if domain in href.lower():
                    found_profiles.append({
                        "platform": platform,
                        "url": href,
                        "link_text": link_text[:100],
                        "source": "link"
                    })
    except Exception:
        pass
    
    return found_profiles

def extract_social_links(content, base_url):
    """Extract social media links from HTML content"""
    if not BEAUTIFULSOUP_AVAILABLE:
        return extract_social_links_regex(content, base_url)
    
    social_platforms = get_social_platforms()
    found_profiles = []
    
    try:
        soup = BeautifulSoup(content, 'html.parser')
        
        # Check all links on the page
        for link in soup.find_all('a', href=True):
            href = link['href']
            link_text = link.get_text(strip=True)
            
            # Convert relative URLs to absolute
            if href.startswith('/'):
                href = urljoin(base_url, href)
            
            # Check if link contains social media domain
            for domain, platform in social_platforms.items():
                if domain in href.lower():
                    found_profiles.append({
                        "platform": platform,
                        "url": href,
                        "link_text": link_text[:100],  # Truncate long text
                        "source": "link"
                    })
        
        # Check meta tags for social media properties
        for meta in soup.find_all('meta'):
            content_attr = meta.get('content', '')
            property_attr = meta.get('property', '')
            name_attr = meta.get('name', '')
            
            # Check various meta tag attributes
            for attr_value in [content_attr, property_attr, name_attr]:
                for domain, platform in social_platforms.items():
                    if domain in attr_value.lower():
                        found_profiles.append({
                            "platform": platform,
                            "url": content_attr if content_attr else attr_value,
                            "link_text": "Meta tag",
                            "source": "meta"
                        })
        
        # Check for social media usernames in content
        social_patterns = {
            'Twitter/X': r'@([A-Za-z0-9_]{1,15})',
            'Instagram': r'instagram\.com/([A-Za-z0-9_.]{1,30})',
            'GitHub': r'github\.com/([A-Za-z0-9_-]{1,39})'
        }
        
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if platform == 'Twitter/X':
                    url = f"https://twitter.com/{match}"
                elif platform == 'Instagram':
                    url = f"https://instagram.com/{match}"
                elif platform == 'GitHub':
                    url = f"https://github.com/{match}"
                
                found_profiles.append({
                    "platform": platform,
                    "url": url,
                    "link_text": f"@{match}",
                    "source": "pattern"
                })
    
    except Exception:
        pass
    
    return found_profiles

def remove_duplicates(profiles):
    """Remove duplicate social media profiles"""
    seen_urls = set()
    unique_profiles = []
    
    for profile in profiles:
        url_clean = profile['url'].lower().rstrip('/')
        if url_clean not in seen_urls:
            seen_urls.add(url_clean)
            unique_profiles.append(profile)
    
    return unique_profiles

def validate_social_profiles(profiles):
    """Basic validation of social media profiles"""
    validated_profiles = []
    
    for profile in profiles:
        url = profile['url']
        
        # Skip obviously invalid URLs
        if not url or len(url) < 10:
            continue
        
        # Skip URLs that are clearly not social media profiles
        if any(skip in url.lower() for skip in [
            '.png', '.jpg', '.gif', '.css', '.js', 'mailto:',
            'tel:', 'javascript:', '#'
        ]):
            continue
        
        validated_profiles.append(profile)
    
    return validated_profiles

def discover_social_media(target):
    """Discover social media profiles for target"""
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    all_profiles = []
    
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(target, headers=headers, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code == 200:
            profiles = extract_social_links(response.text, target)
            all_profiles.extend(profiles)
    
    except Exception:
        pass
    
    # Remove duplicates and validate
    unique_profiles = remove_duplicates(all_profiles)
    validated_profiles = validate_social_profiles(unique_profiles)
    
    return validated_profiles

def main(target):
    """Main execution with clean output"""
    print(f"[I] Social Media Discovery - {target}")
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
        print("[I] Searching for social media profiles...")
        print()
        
        # Discover social media profiles
        profiles = discover_social_media(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if profiles:
            # Group by platform for analysis
            platform_groups = {}
            for profile in profiles:
                platform = profile['platform']
                if platform not in platform_groups:
                    platform_groups[platform] = []
                platform_groups[platform].append(profile)
            
            # Assess security risk
            security_findings, severity = assess_social_media_security_risk(profiles, platform_groups)
            
            print(f"[{severity}] SOCIAL PROFILES: Found {len(profiles)} social media profiles")
            
            # Display security analysis
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display results grouped by platform with risk assessment
            for platform in sorted(platform_groups.keys()):
                platform_profiles = platform_groups[platform]
                platform_risk = get_platform_risk_level(platform)
                
                print(f"[{platform_risk}] {platform.upper()} ({len(platform_profiles)}):")
                for profile in platform_profiles:
                    source_names = {"link": "Direct Link", "meta": "Meta Tag", "pattern": "Pattern Match"}
                    source_name = source_names.get(profile['source'], "Unknown")
                    
                    print(f"  [{platform_risk}] {profile['url']}")
                    print(f"    - Source: {source_name}")
                    if profile['link_text'] and profile['link_text'] != "Meta tag":
                        print(f"    - Context: {profile['link_text']}")
                print()
            
            # Platform summary
            print("[I] PLATFORM SUMMARY:")
            high_risk = [p for p in platform_groups.keys() if get_platform_risk_level(p) == "H"]
            medium_risk = [p for p in platform_groups.keys() if get_platform_risk_level(p) == "W"]
            low_risk = [p for p in platform_groups.keys() if get_platform_risk_level(p) == "I"]
            
            if high_risk:
                print(f"  [H] High-risk platforms: {', '.join(high_risk)}")
            if medium_risk:
                print(f"  [W] Medium-risk platforms: {', '.join(medium_risk)}")
            if low_risk:
                print(f"  [I] Low-risk platforms: {', '.join(low_risk)}")
            
            print()
            print(f"[I] Execution time: {execution_time:.2f}s")
            
            return {
                "status": "SUCCESS",
                "data": {
                    "profiles": profiles,
                    "platforms": list(platform_groups.keys()),
                    "platform_groups": platform_groups
                },
                "security_findings": security_findings,
                "severity": severity,
                "count": len(profiles),
                "execution_time": execution_time
            }
        else:
            print("[I] NO DATA: No social media profiles found")
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Discovery stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during social media discovery")
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
        print("Usage: python social_media.py <url_or_domain>")
        print("Example: python social_media.py example.com")
        sys.exit(1)