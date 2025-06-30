#!/usr/bin/env python3
"""
Improved Exposed Environment Files Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
UPDATED: Integrated with centralized findings system
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

# NEW: Import findings system
try:
    from config.findings_rules import evaluate_findings, display_findings_result
    FINDINGS_AVAILABLE = True
except ImportError:
    print("[W] Findings system not available - running in legacy mode")
    FINDINGS_AVAILABLE = False

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
        '.env.development', '.env.staging', 'config.yml', 'application.yml',
        'docker-compose.yml', 'database.json'
    ]
    
    low_risk_files = [
        '.env.example', '.env.sample', 'Dockerfile', '.dockerignore'
    ]
    
    # Base risk on filename
    if filename in high_risk_files:
        base_risk = "C"
    elif filename in medium_risk_files:
        base_risk = "H"
    elif filename in low_risk_files:
        base_risk = "W"
    else:
        base_risk = "W"
    
    # Adjust based on content analysis
    if analysis:
        risk_level = analysis.get('risk_level', 'LOW')
        sensitive_count = len(analysis.get('sensitive_items', []))
        
        if risk_level == "CRITICAL" or sensitive_count > 10:
            return "C"
        elif risk_level == "HIGH" or sensitive_count > 5:
            return "C" if base_risk in ["C", "H"] else "H"
        elif risk_level == "MEDIUM" or sensitive_count > 0:
            return "H" if base_risk == "C" else ("H" if base_risk == "H" else "W")
    
    return base_risk

def analyze_file_content(content, filename):
    """Analyze file content for sensitive information"""
    # Patterns for different types of sensitive data
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
            r'aws[_-]?access[_-]?key[_-]?=[\s]*["\']?([A-Z0-9]{20})["\']?',
            r'aws[_-]?secret[_-]?=[\s]*["\']?([A-Za-z0-9/+=]{40})["\']?'
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
    """Main execution with enhanced findings evaluation"""
    print(f"[I] Exposed Environment Files Analysis - {target}")
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
        print("[I] Scanning for exposed environment files...")
        print()
        
        # Perform environment file scanning (your existing logic)
        found_files = scan_exposed_files(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Separate accessible and protected files
        accessible_files = [f for f in found_files if f.get('accessible', False)]
        protected_files = [f for f in found_files if not f.get('accessible', True)]
        
        # Calculate total secrets found
        total_secrets = sum(
            len(f.get('analysis', {}).get('sensitive_items', []))
            for f in accessible_files
        )
        
        # Prepare scan data for findings evaluation
        scan_data = {
            "accessible_files": accessible_files,
            "protected_files": protected_files,
            "total_files_found": len(found_files),
            "total_accessible": len(accessible_files),
            "total_secrets": total_secrets,
            "scan_completed": True,
            "target": target
        }
        
        if accessible_files:
            # Group files by risk level (keep existing logic)
            risk_groups = {"C": [], "H": [], "W": [], "I": []}
            for file_info in accessible_files:
                risk = file_info.get('security_risk', 'I')
                risk_groups[risk].append(file_info)
            
            # Determine overall severity
            if risk_groups["C"]:
                overall_severity = "C"
            elif risk_groups["H"]:
                overall_severity = "H"
            elif risk_groups["W"]:
                overall_severity = "W"
            else:
                overall_severity = "I"
            
            print(f"[{overall_severity}] EXPOSED FILES FOUND: {len(accessible_files)} files publicly accessible")
            if total_secrets > 0:
                print(f"[C] CRITICAL: {total_secrets} sensitive items discovered in exposed files")
            print()
            
            # Display results by risk level (keep existing display)
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
        else:
            if protected_files:
                print(f"[S] PROTECTED: Found {len(protected_files)} files but they are properly protected")
                overall_severity = "I"
            else:
                print("[S] SECURE: No exposed environment files found")
                overall_severity = "I"
        
        print()
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("exposed_env_files.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            if accessible_files:
                findings = [f"Found {len(accessible_files)} exposed environment files"]
                if total_secrets > 0:
                    findings.append(f"Discovered {total_secrets} sensitive items in files")
            else:
                findings = ["No environment files exposed"]
            
            findings_result = {
                "success": True,  # Scan completed successfully
                "severity": overall_severity,
                "findings": findings,
                "has_findings": len(accessible_files) > 0,
                "category": "Environment File Analysis"
            }
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        print()
        
        # Return standardized format
        return {
            "status": "SUCCESS",  # Always success if scan completes
            "data": scan_data,
            "findings": findings_result,
            "execution_time": execution_time,
            "target": target,
            # Keep legacy fields for backward compatibility
            "count": len(accessible_files),
            "secrets_count": total_secrets,
            "severity": findings_result["severity"]
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Scan stopped by user")
        
        interrupt_findings = {
            "success": False,
            "severity": "I",
            "findings": ["Environment file scan interrupted by user"],
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
            print("[T] TIMEOUT: Request timeout during file scanning")
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
            "findings": [f"Environment file scan failed: {error_msg}"],
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
        print("Usage: python exposed_env_files.py <url_or_domain>")
        print("Example: python exposed_env_files.py example.com")
        sys.exit(1)