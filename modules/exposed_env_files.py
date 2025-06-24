#!/usr/bin/env python3
"""
Improved Exposed Environment Files Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
"""

import os
import sys
import requests
import re
from datetime import datetime
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def get_env_file_patterns():
    """Get list of environment files to check"""
    return [
        # Environment files
        '.env',
        '.env.local',
        '.env.development',
        '.env.production',
        '.env.staging',
        '.env.test',
        '.env.backup',
        '.env.example',
        '.env.sample',
        'env',
        'environment',
        
        # Configuration files
        'config.env',
        'app.env',
        'database.env',
        'docker.env',
        '.env.docker',
        
        # Other sensitive config files
        'config.php',
        'wp-config.php',
        'settings.py',
        'local_settings.py',
        'config.yml',
        'config.yaml',
        'application.yml',
        'application.properties',
        
        # Docker and container configs
        'docker-compose.yml',
        'docker-compose.yaml',
        'Dockerfile',
        '.dockerignore',
        
        # Other potentially sensitive files
        'secrets.json',
        'credentials.json',
        'keys.json',
        'database.json',
        'config.json'
    ]

def assess_file_security_risk(filename, analysis):
    """Assess security risk level of exposed file"""
    high_risk_files = [
        '.env', '.env.production', '.env.local', 'config.php', 'wp-config.php',
        'settings.py', 'secrets.json', 'credentials.json', 'keys.json'
    ]
    
    medium_risk_files = [
        '.env.development', '.env.staging', '.env.test', 'config.yml', 
        'application.yml', 'database.json'
    ]
    
    # Base risk from filename
    if filename in high_risk_files:
        base_risk = "H"
    elif filename in medium_risk_files:
        base_risk = "W"
    else:
        base_risk = "I"
    
    # Elevate risk based on content analysis
    content_risk = analysis.get('risk_level', 'LOW')
    sensitive_count = len(analysis.get('sensitive_items', []))
    
    # Critical conditions
    if content_risk == 'CRITICAL' or sensitive_count >= 10:
        return "C"
    
    # High risk conditions
    if content_risk == 'HIGH' or sensitive_count >= 5 or base_risk == "H":
        return "H"
    
    # Warning conditions
    if content_risk == 'MEDIUM' or sensitive_count >= 1 or base_risk == "W":
        return "W"
    
    return "I"

def analyze_file_content(content, filename):
    """Analyze file content for sensitive information"""
    if not content:
        return {"sensitive_items": [], "risk_level": "LOW"}
    
    sensitive_patterns = {
        'API Keys': [
            r'api[_-]?key[_-]?=[\s]*["\']?([A-Za-z0-9_-]{20,})["\']?',
            r'secret[_-]?key[_-]?=[\s]*["\']?([A-Za-z0-9_-]{20,})["\']?',
            r'access[_-]?token[_-]?=[\s]*["\']?([A-Za-z0-9_-]{20,})["\']?'
        ],
        'Database Credentials': [
            r'db[_-]?password[_-]?=[\s]*["\']?([^"\'\s]+)["\']?',
            r'database[_-]?password[_-]?=[\s]*["\']?([^"\'\s]+)["\']?',
            r'mysql[_-]?password[_-]?=[\s]*["\']?([^"\'\s]+)["\']?',
            r'postgres[_-]?password[_-]?=[\s]*["\']?([^"\'\s]+)["\']?'
        ],
        'AWS Credentials': [
            r'aws[_-]?access[_-]?key[_-]?id[_-]?=[\s]*["\']?([A-Z0-9]{20})["\']?',
            r'aws[_-]?secret[_-]?access[_-]?key[_-]?=[\s]*["\']?([A-Za-z0-9/+=]{40})["\']?'
        ],
        'Email Credentials': [
            r'mail[_-]?password[_-]?=[\s]*["\']?([^"\'\s]+)["\']?',
            r'smtp[_-]?password[_-]?=[\s]*["\']?([^"\'\s]+)["\']?'
        ],
        'Encryption Keys': [
            r'encryption[_-]?key[_-]?=[\s]*["\']?([A-Za-z0-9/+=]{32,})["\']?',
            r'cipher[_-]?key[_-]?=[\s]*["\']?([A-Za-z0-9/+=]{32,})["\']?',
            r'jwt[_-]?secret[_-]?=[\s]*["\']?([A-Za-z0-9/+=]{32,})["\']?'
        ],
        'Payment Credentials': [
            r'stripe[_-]?secret[_-]?=[\s]*["\']?([A-Za-z0-9_-]{32,})["\']?',
            r'paypal[_-]?secret[_-]?=[\s]*["\']?([A-Za-z0-9_-]{32,})["\']?'
        ]
    }
    
    sensitive_items = []
    content_lower = content.lower()
    
    for category, patterns in sensitive_patterns.items():
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Mask the sensitive value
                value = match.group(1) if len(match.groups()) > 0 else match.group(0)
                masked_value = value[:4] + "*" * (len(value) - 8) + value[-4:] if len(value) > 8 else "*" * len(value)
                
                sensitive_items.append({
                    "category": category,
                    "pattern": pattern.split('=')[0],
                    "masked_value": masked_value,
                    "line_number": content[:match.start()].count('\n') + 1
                })
    
    # Determine risk level
    if len(sensitive_items) > 10:
        risk_level = "CRITICAL"
    elif len(sensitive_items) > 5:
        risk_level = "HIGH"
    elif len(sensitive_items) > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return {
        "sensitive_items": sensitive_items,
        "risk_level": risk_level,
        "total_lines": content.count('\n') + 1,
        "file_size": len(content)
    }

def check_env_file(base_url, filename, session):
    """Check if an environment file exists and analyze it"""
    try:
        url = urljoin(base_url, filename)
        headers = {'User-Agent': USER_AGENT}
        
        response = session.get(url, headers=headers, timeout=5, allow_redirects=False)
        
        if response.status_code == 200 and response.content:
            content = response.text
            analysis = analyze_file_content(content, filename)
            
            return {
                "filename": filename,
                "url": url,
                "status_code": response.status_code,
                "file_size": len(content),
                "content_type": response.headers.get('content-type', 'unknown'),
                "analysis": analysis,
                "accessible": True,
                "security_risk": assess_file_security_risk(filename, analysis)
            }
        elif response.status_code in [403, 401]:
            # File exists but access denied
            return {
                "filename": filename,
                "url": url,
                "status_code": response.status_code,
                "file_size": 0,
                "accessible": False,
                "note": "File exists but access denied"
            }
    except:
        pass
    
    return None

def scan_exposed_files(target, max_workers=10):
    """Scan for exposed environment files"""
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    env_files = get_env_file_patterns()
    found_files = []
    
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(check_env_file, target, filename, session): filename 
                for filename in env_files
            }
            
            for future in as_completed(future_to_file):
                result = future.result()
                if result:
                    found_files.append(result)
    
    return sorted(found_files, key=lambda x: x.get('security_risk', 'I'), reverse=True)

def main(target):
    """Main execution with clean output"""
    print(f"[I] Exposed Environment Files Check - {target}")
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
        print("[I] Scanning for exposed environment files...")
        print()
        
        # Scan for exposed files
        found_files = scan_exposed_files(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if found_files:
            # Separate accessible and inaccessible files
            accessible_files = [f for f in found_files if f.get('accessible', False)]
            protected_files = [f for f in found_files if not f.get('accessible', False)]
            
            if accessible_files:
                # Determine overall severity
                risk_levels = [f.get('security_risk', 'I') for f in accessible_files]
                if 'C' in risk_levels:
                    overall_severity = "C"
                elif 'H' in risk_levels:
                    overall_severity = "H"
                elif 'W' in risk_levels:
                    overall_severity = "W"
                else:
                    overall_severity = "I"
                
                print(f"[{overall_severity}] EXPOSED FILES: Found {len(accessible_files)} accessible environment files")
                if protected_files:
                    print(f"[I] Protected: {len(protected_files)} files exist but are access-denied")
                
                # Security analysis
                total_secrets = sum(len(f.get('analysis', {}).get('sensitive_items', [])) for f in accessible_files)
                if total_secrets > 0:
                    print(f"[C] Security Impact: {total_secrets} sensitive credentials exposed")
                print()
                
                # Group files by security risk
                risk_groups = {"C": [], "H": [], "W": [], "I": []}
                for file_info in accessible_files:
                    risk = file_info.get('security_risk', 'I')
                    risk_groups[risk].append(file_info)
                
                # Display by risk level (highest first)
                for risk_level in ['C', 'H', 'W', 'I']:
                    if risk_groups[risk_level]:
                        files = risk_groups[risk_level]
                        risk_names = {'C': 'CRITICAL', 'H': 'HIGH RISK', 'W': 'WARNING', 'I': 'INFORMATIONAL'}
                        
                        print(f"[{risk_level}] {risk_names[risk_level]} FILES ({len(files)}):")
                        for file_info in files:
                            analysis = file_info.get('analysis', {})
                            sensitive_count = len(analysis.get('sensitive_items', []))
                            
                            print(f"  [{risk_level}] {file_info['filename']} ({file_info['file_size']} bytes)")
                            print(f"    - URL: {file_info['url']}")
                            
                            if sensitive_count > 0:
                                print(f"    - Secrets: {sensitive_count} sensitive items detected")
                                
                                # Show critical sensitive items
                                for item in analysis.get('sensitive_items', [])[:3]:
                                    print(f"      * {item['category']}: {item['masked_value']} (line {item['line_number']})")
                            
                            if sensitive_count > 3:
                                print(f"      * ... and {sensitive_count - 3} more items")
                        print()
                
                print(f"[I] Execution time: {execution_time:.2f}s")
                
                return {
                    "status": "SUCCESS",
                    "data": {
                        "accessible_files": accessible_files,
                        "protected_files": protected_files,
                        "risk_summary": {level: len(files) for level, files in risk_groups.items() if files}
                    },
                    "severity": overall_severity,
                    "count": len(accessible_files),
                    "secrets_count": total_secrets,
                    "execution_time": execution_time
                }
            else:
                print(f"[S] PROTECTED: Found {len(protected_files)} files but they are properly protected")
                print(f"[I] Execution time: {execution_time:.2f}s")
                return {
                    "status": "PROTECTED",
                    "data": {"protected_files": protected_files},
                    "count": len(protected_files),
                    "execution_time": execution_time
                }
        else:
            print("[S] SECURE: No exposed environment files found")
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Scan stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during file scanning")
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
        print("Usage: python exposed_env_files.py <url_or_domain>")
        print("Example: python exposed_env_files.py example.com")
        sys.exit(1)