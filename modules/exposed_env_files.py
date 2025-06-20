#!/usr/bin/env python3
"""
Improved Exposed Environment Files Module - Clean Output with Success/Failure Indicators
"""

import os
import sys
import requests
import re
from datetime import datetime
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import USER_AGENT, DEFAULT_TIMEOUT

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
                "accessible": True
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
    
    return sorted(found_files, key=lambda x: x.get('analysis', {}).get('risk_level', 'LOW'), reverse=True)

def main(target):
    """Main execution with clean output"""
    print(f"🔍 Exposed Environment Files Check - {target}")
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
        print("🔍 Scanning for exposed environment files...")
        print()
        
        # Scan for exposed files
        found_files = scan_exposed_files(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if found_files:
            # Separate accessible and inaccessible files
            accessible_files = [f for f in found_files if f.get('accessible', False)]
            protected_files = [f for f in found_files if not f.get('accessible', False)]
            
            if accessible_files:
                print(f"⚠️  CRITICAL: Found {len(accessible_files)} exposed environment files")
                print(f"🔒 Protected: {len(protected_files)} files exist but are protected")
                print(f"⏱️  Execution time: {execution_time:.2f}s")
                print()
                
                # Display accessible files by risk level
                risk_groups = {}
                for file_info in accessible_files:
                    risk = file_info.get('analysis', {}).get('risk_level', 'LOW')
                    if risk not in risk_groups:
                        risk_groups[risk] = []
                    risk_groups[risk].append(file_info)
                
                # Display by risk level (highest first)
                for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if risk_level in risk_groups:
                        files = risk_groups[risk_level]
                        risk_emoji = {
                            'CRITICAL': '🚨',
                            'HIGH': '⚠️',
                            'MEDIUM': '⚡',
                            'LOW': 'ℹ️'
                        }[risk_level]
                        
                        print(f"{risk_emoji} {risk_level} Risk Files ({len(files)}):")
                        for file_info in files:
                            analysis = file_info.get('analysis', {})
                            sensitive_count = len(analysis.get('sensitive_items', []))
                            
                            print(f"   • {file_info['filename']} ({file_info['file_size']} bytes)")
                            if sensitive_count > 0:
                                print(f"     └─ {sensitive_count} sensitive items detected")
                                
                                # Show first few sensitive items
                                for item in analysis.get('sensitive_items', [])[:3]:
                                    print(f"        - {item['category']}: {item['masked_value']}")
                        print()
                
                return {
                    "status": "SUCCESS",
                    "data": {
                        "accessible_files": accessible_files,
                        "protected_files": protected_files,
                        "risk_summary": {level: len(files) for level, files in risk_groups.items()}
                    },
                    "count": len(accessible_files),
                    "execution_time": execution_time,
                    "severity": "CRITICAL" if any(f.get('analysis', {}).get('risk_level') == 'CRITICAL' for f in accessible_files) else "HIGH"
                }
            else:
                print(f"🔒 PROTECTED: Found {len(protected_files)} files but they are properly protected")
                print(f"⏱️  Execution time: {execution_time:.2f}s")
                return {
                    "status": "PROTECTED",
                    "data": {"protected_files": protected_files},
                    "count": len(protected_files),
                    "execution_time": execution_time
                }
        else:
            print("✅ SECURE: No exposed environment files found")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Scan stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("⏰ TIMEOUT: Request timeout during file scanning")
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
        print("Usage: python exposed_env_files.py <url_or_domain>")
        print("Example: python exposed_env_files.py example.com")
        sys.exit(1)