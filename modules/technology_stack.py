#!/usr/bin/env python3
"""
Improved Technology Stack Module - Clean Output with Success/Failure Indicators
"""

import os
import sys
import requests
import re
from datetime import datetime
from urllib.parse import urljoin

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import USER_AGENT, DEFAULT_TIMEOUT

def detect_from_headers(headers):
    """Detect technologies from HTTP headers"""
    technologies = {
        'servers': [],
        'frameworks': [],
        'languages': [],
        'security': []
    }
    
    # Server detection
    server = headers.get('server', '').lower()
    if server:
        if 'apache' in server:
            technologies['servers'].append('Apache')
        if 'nginx' in server:
            technologies['servers'].append('Nginx')
        if 'iis' in server:
            technologies['servers'].append('IIS')
        if 'cloudflare' in server:
            technologies['servers'].append('Cloudflare')
    
    # Framework/Language detection from X-Powered-By
    x_powered_by = headers.get('x-powered-by', '').lower()
    if x_powered_by:
        if 'php' in x_powered_by:
            technologies['languages'].append('PHP')
        if 'asp.net' in x_powered_by:
            technologies['frameworks'].append('ASP.NET')
        if 'express' in x_powered_by:
            technologies['frameworks'].append('Express.js')
    
    # Security headers
    security_headers = [
        'strict-transport-security', 'content-security-policy',
        'x-frame-options', 'x-content-type-options'
    ]
    for header in security_headers:
        if header in headers:
            technologies['security'].append(header.replace('-', ' ').title())
    
    return technologies

def detect_from_content(content):
    """Detect technologies from HTML content"""
    technologies = {
        'cms': [],
        'frameworks': [],
        'libraries': [],
        'analytics': [],
        'languages': []
    }
    
    content_lower = content.lower()
    
    # CMS Detection
    cms_patterns = {
        'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
        'Joomla': ['/components/', '/modules/', 'joomla'],
        'Drupal': ['/sites/default/', '/modules/', 'drupal'],
        'Magento': ['/skin/frontend/', 'magento', 'mage/cookies'],
        'Shopify': ['shopify', 'shop.js', 'shopify-features']
    }
    
    for cms, patterns in cms_patterns.items():
        if any(pattern in content_lower for pattern in patterns):
            technologies['cms'].append(cms)
    
    # JavaScript Frameworks
    js_patterns = {
        'React': ['react', '_react', 'reactdom'],
        'Vue.js': ['vue.js', '__vue__', 'vue-router'],
        'Angular': ['angular', 'ng-version', '@angular'],
        'jQuery': ['jquery', '$/', 'jquery-'],
        'Bootstrap': ['bootstrap', 'btn-', 'col-md-'],
        'Tailwind CSS': ['tailwind', 'tw-', 'tailwindcss']
    }
    
    for framework, patterns in js_patterns.items():
        if any(pattern in content_lower for pattern in patterns):
            if framework in ['jQuery', 'Bootstrap', 'Tailwind CSS']:
                technologies['libraries'].append(framework)
            else:
                technologies['frameworks'].append(framework)
    
    # Analytics
    analytics_patterns = {
        'Google Analytics': ['google-analytics', 'gtag(', 'ga('],
        'Google Tag Manager': ['googletagmanager', 'gtm.js'],
        'Facebook Pixel': ['facebook.com/pixel', 'fbevents.js'],
        'Hotjar': ['hotjar', 'hj(']
    }
    
    for analytics, patterns in analytics_patterns.items():
        if any(pattern in content_lower for pattern in patterns):
            technologies['analytics'].append(analytics)
    
    # Programming Languages (from file extensions or patterns)
    if '.php' in content_lower or '<?php' in content_lower:
        technologies['languages'].append('PHP')
    if '.asp' in content_lower or '<%' in content_lower:
        technologies['languages'].append('ASP')
    if '.jsp' in content_lower:
        technologies['languages'].append('Java')
    
    return technologies

def detect_from_files(target):
    """Detect technologies by checking specific files"""
    technologies = {
        'cms': [],
        'frameworks': [],
        'security': []
    }
    
    # Files to check
    check_files = [
        ('/wp-login.php', 'WordPress', 'cms'),
        ('/administrator/', 'Joomla', 'cms'),
        ('/user/login', 'Drupal', 'cms'),
        ('/robots.txt', 'Robots.txt', 'security'),
        ('/sitemap.xml', 'XML Sitemap', 'security'),
        ('/.well-known/security.txt', 'Security.txt', 'security')
    ]
    
    for file_path, tech_name, category in check_files:
        try:
            url = urljoin(target, file_path)
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                technologies[category].append(tech_name)
        except:
            continue
    
    return technologies

def merge_technologies(tech_lists):
    """Merge multiple technology detection results"""
    merged = {
        'servers': [],
        'frameworks': [],
        'cms': [],
        'languages': [],
        'libraries': [],
        'analytics': [],
        'security': []
    }
    
    for tech_dict in tech_lists:
        for category, items in tech_dict.items():
            if category in merged:
                merged[category].extend(items)
    
    # Remove duplicates
    for category in merged:
        merged[category] = list(set(merged[category]))
    
    return merged

def detect_technology_stack(target):
    """Comprehensive technology stack detection"""
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(target, headers=headers, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code != 200:
            return None
        
        # Detect from different sources
        header_tech = detect_from_headers(response.headers)
        content_tech = detect_from_content(response.text)
        file_tech = detect_from_files(target)
        
        # Merge all detections
        all_technologies = merge_technologies([header_tech, content_tech, file_tech])
        
        return all_technologies
        
    except Exception:
        return None

def main(target):
    """Main execution with clean output"""
    print(f"🔍 Technology Stack Detection - {target}")
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
        print("🔍 Detecting technologies...")
        print()
        
        # Detect technology stack
        technologies = detect_technology_stack(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if technologies:
            # Count total technologies found
            total_count = sum(len(techs) for techs in technologies.values())
            
            if total_count > 0:
                print(f"✅ SUCCESS: Detected {total_count} technologies")
                print(f"⏱️  Execution time: {execution_time:.2f}s")
                print()
                
                # Display results by category
                category_icons = {
                    'servers': '🖥️',
                    'frameworks': '🏗️',
                    'cms': '📝',
                    'languages': '💻',
                    'libraries': '📚',
                    'analytics': '📊',
                    'security': '🔒'
                }
                
                for category, techs in technologies.items():
                    if techs:
                        icon = category_icons.get(category, '🔧')
                        category_name = category.replace('_', ' ').title()
                        print(f"{icon} {category_name} ({len(techs)}):")
                        for tech in sorted(techs):
                            print(f"   • {tech}")
                        print()
                
                return {
                    "status": "SUCCESS",
                    "data": technologies,
                    "count": total_count,
                    "execution_time": execution_time
                }
            else:
                print("ℹ️  NO DATA: No technologies detected")
                print(f"⏱️  Execution time: {execution_time:.2f}s")
                return {"status": "NO_DATA", "execution_time": execution_time}
        else:
            print("ℹ️  NO DATA: Unable to analyze target")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Detection stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("⏰ TIMEOUT: Request timeout during technology detection")
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
        print("Usage: python technology_stack.py <url_or_domain>")
        print("Example: python technology_stack.py example.com")
        sys.exit(1)