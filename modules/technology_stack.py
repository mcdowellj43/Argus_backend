#!/usr/bin/env python3
"""
Improved Technology Stack Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
"""

import os
import sys
import requests
import re
from datetime import datetime
from urllib.parse import urljoin

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

def assess_technology_security_risk(technologies):
    """Assess security risk of detected technologies"""
    findings = []
    severity = "I"
    
    if not technologies:
        return findings, severity
    
    # High-risk/outdated technologies
    high_risk_tech = {
        'PHP': 'Potential version vulnerabilities if outdated',
        'ASP': 'Legacy technology with known security issues',
        'jQuery': 'Often outdated versions with XSS vulnerabilities',
        'WordPress': 'Common target for attacks, requires updates',
        'Joomla': 'Frequent security vulnerabilities',
        'Magento': 'Complex platform with security challenges'
    }
    
    # Positive security indicators
    security_positives = [
        'Strict Transport Security', 'Content Security Policy',
        'X Frame Options', 'X Content Type Options', 'Security.txt'
    ]
    
    # Framework security considerations
    framework_risks = {
        'React': 'Generally secure but depends on implementation',
        'Vue.js': 'Good security model with proper usage',
        'Angular': 'Built-in XSS protection',
        'Express.js': 'Requires careful configuration'
    }
    
    high_risk_found = []
    security_headers_found = []
    outdated_tech_found = []
    
    # Check all technologies for risks
    for category, tech_list in technologies.items():
        for tech in tech_list:
            if tech in high_risk_tech:
                high_risk_found.append(tech)
                
            if tech in security_positives:
                security_headers_found.append(tech)
                
            # Check for potentially outdated technologies
            if tech in ['ASP', 'jQuery'] or 'old' in tech.lower():
                outdated_tech_found.append(tech)
    
    # Determine severity based on findings
    if outdated_tech_found or len(high_risk_found) >= 3:
        severity = "H"
        findings.append(f"High-risk technologies detected: {len(high_risk_found + outdated_tech_found)} concerning technologies")
        
    elif high_risk_found:
        severity = "W"
        findings.append(f"Moderate security concerns: {len(high_risk_found)} technologies require attention")
    
    # Specific technology warnings
    for tech in high_risk_found[:3]:  # Show first 3
        if tech in high_risk_tech:
            findings.append(f"Security concern: {tech} - {high_risk_tech[tech]}")
    
    # Security header assessment
    if len(security_headers_found) >= 3:
        findings.append(f"Good security posture: {len(security_headers_found)} security headers implemented")
    elif len(security_headers_found) >= 1:
        findings.append(f"Basic security measures: {len(security_headers_found)} security headers found")
    else:
        if severity == "I":
            severity = "W"
        findings.append("Missing security headers: No security headers detected")
    
    # Technology stack complexity assessment
    total_technologies = sum(len(tech_list) for tech_list in technologies.values())
    if total_technologies >= 15:
        findings.append(f"Complex technology stack: {total_technologies} technologies detected (increased attack surface)")
    
    return findings, severity

def get_technology_risk_level(tech_name, category):
    """Determine risk level for individual technologies"""
    high_risk_technologies = ['PHP', 'ASP', 'WordPress', 'Joomla', 'Magento']
    medium_risk_technologies = ['jQuery', 'Express.js', 'IIS']
    
    if tech_name in high_risk_technologies:
        return "H"
    elif tech_name in medium_risk_technologies:
        return "W"
    elif category == 'security':
        return "S"  # Security features are positive
    else:
        return "I"

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
        ('strict-transport-security', 'Strict Transport Security'),
        ('content-security-policy', 'Content Security Policy'),
        ('x-frame-options', 'X Frame Options'),
        ('x-content-type-options', 'X Content Type Options'),
        ('referrer-policy', 'Referrer Policy'),
        ('permissions-policy', 'Permissions Policy')
    ]
    for header, display_name in security_headers:
        if header in headers:
            technologies['security'].append(display_name)
    
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
        'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json', 'wp-admin'],
        'Joomla': ['/components/', '/modules/', 'joomla', '/administrator/'],
        'Drupal': ['/sites/default/', '/modules/', 'drupal'],
        'Magento': ['/skin/frontend/', 'magento', 'mage/cookies'],
        'Shopify': ['shopify', 'shop.js', 'shopify-features'],
        'Wix': ['wix.com', 'wixstatic'],
        'Squarespace': ['squarespace', 'squarespace.com']
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
        'Tailwind CSS': ['tailwind', 'tw-', 'tailwindcss'],
        'Foundation': ['foundation', 'zurb'],
        'Materialize': ['materialize']
    }
    
    for framework, patterns in js_patterns.items():
        if any(pattern in content_lower for pattern in patterns):
            if framework in ['jQuery', 'Bootstrap', 'Tailwind CSS', 'Foundation', 'Materialize']:
                technologies['libraries'].append(framework)
            else:
                technologies['frameworks'].append(framework)
    
    # Analytics and Tracking
    analytics_patterns = {
        'Google Analytics': ['google-analytics', 'gtag(', 'ga('],
        'Google Tag Manager': ['googletagmanager', 'gtm.js'],
        'Facebook Pixel': ['facebook.com/pixel', 'fbevents.js'],
        'Hotjar': ['hotjar', 'hj('],
        'Adobe Analytics': ['adobe analytics', 's_code.js'],
        'Mixpanel': ['mixpanel']
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
    if '.py' in content_lower or 'django' in content_lower:
        technologies['languages'].append('Python')
    
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
    print(f"[I] Technology Stack Detection - {target}")
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
        print("[I] Detecting technologies...")
        print()
        
        # Detect technology stack
        technologies = detect_technology_stack(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if technologies:
            # Count total technologies found
            total_count = sum(len(techs) for techs in technologies.values())
            
            if total_count > 0:
                # Assess security risk
                security_findings, severity = assess_technology_security_risk(technologies)
                
                print(f"[{severity}] TECHNOLOGIES DETECTED: {total_count} technologies identified")
                
                # Display security analysis
                if security_findings:
                    print(f"[{severity}] Security Risk Analysis:")
                    for finding in security_findings:
                        print(f"  [{severity}] {finding}")
                    print()
                
                # Display results by category with risk assessment
                category_names = {
                    'servers': 'WEB SERVERS',
                    'frameworks': 'FRAMEWORKS',
                    'cms': 'CONTENT MANAGEMENT',
                    'languages': 'PROGRAMMING LANGUAGES',
                    'libraries': 'LIBRARIES & UI',
                    'analytics': 'ANALYTICS & TRACKING',
                    'security': 'SECURITY FEATURES'
                }
                
                for category, techs in technologies.items():
                    if techs:
                        category_name = category_names.get(category, category.upper())
                        print(f"[I] {category_name} ({len(techs)}):")
                        for tech in sorted(techs):
                            tech_risk = get_technology_risk_level(tech, category)
                            print(f"  [{tech_risk}] {tech}")
                        print()
                
                # Technology risk summary
                high_risk_techs = []
                security_features = []
                
                for category, techs in technologies.items():
                    for tech in techs:
                        risk = get_technology_risk_level(tech, category)
                        if risk == "H":
                            high_risk_techs.append(tech)
                        elif risk == "S":
                            security_features.append(tech)
                
                print("[I] TECHNOLOGY SUMMARY:")
                if high_risk_techs:
                    print(f"  [H] High-risk technologies: {', '.join(high_risk_techs)}")
                if security_features:
                    print(f"  [S] Security features: {', '.join(security_features)}")
                print(f"  [I] Total technologies: {total_count}")
                
                print()
                print(f"[I] Execution time: {execution_time:.2f}s")
                
                return {
                    "status": "SUCCESS",
                    "data": technologies,
                    "security_findings": security_findings,
                    "severity": severity,
                    "count": total_count,
                    "execution_time": execution_time
                }
            else:
                print("[I] NO DATA: No technologies detected")
                print(f"[I] Execution time: {execution_time:.2f}s")
                return {"status": "NO_DATA", "execution_time": execution_time}
        else:
            print("[I] NO DATA: Unable to analyze target")
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Detection stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during technology detection")
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
        print("Usage: python technology_stack.py <url_or_domain>")
        print("Example: python technology_stack.py example.com")
        sys.exit(1)