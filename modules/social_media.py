#!/usr/bin/env python3
"""
Improved Social Media Module - Clean Output with Success/Failure Indicators
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
        'discord.com': 'Discord'
    }

def extract_social_links(content, base_url):
    """Extract social media links from HTML content"""
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
    print(f"🔍 Social Media Discovery - {target}")
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
        print("🔍 Searching for social media profiles...")
        print()
        
        # Discover social media profiles
        profiles = discover_social_media(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if profiles:
            print(f"✅ SUCCESS: Found {len(profiles)} social media profiles")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Group by platform for better display
            platform_groups = {}
            for profile in profiles:
                platform = profile['platform']
                if platform not in platform_groups:
                    platform_groups[platform] = []
                platform_groups[platform].append(profile)
            
            # Display results grouped by platform
            for platform in sorted(platform_groups.keys()):
                platform_profiles = platform_groups[platform]
                print(f"📱 {platform} ({len(platform_profiles)}):")
                for profile in platform_profiles:
                    source_emoji = {"link": "🔗", "meta": "🏷️", "pattern": "🔍"}.get(profile['source'], "📄")
                    print(f"   {source_emoji} {profile['url']}")
                    if profile['link_text'] and profile['link_text'] != "Meta tag":
                        print(f"      └─ Text: {profile['link_text']}")
                print()
            
            return {
                "status": "SUCCESS",
                "data": {
                    "profiles": profiles,
                    "platforms": list(platform_groups.keys()),
                    "platform_groups": platform_groups
                },
                "count": len(profiles),
                "execution_time": execution_time
            }
        else:
            print("ℹ️  NO DATA: No social media profiles found")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Discovery stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("⏰ TIMEOUT: Request timeout during social media discovery")
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
        print("Usage: python social_media.py <url_or_domain>")
        print("Example: python social_media.py example.com")
        sys.exit(1)