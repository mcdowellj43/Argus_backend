#!/usr/bin/env python3
"""
Enhanced Content Discovery Module - Clean Output with Centralized Binary Findings System
Fixed for Windows Unicode encoding issues
"""

import os
import sys
import requests
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

# NEW: Import findings system
try:
    from config.findings_rules import evaluate_findings, display_findings_result
    FINDINGS_AVAILABLE = True
except ImportError:
    print("[W] Findings system not available - running in legacy mode")
    FINDINGS_AVAILABLE = False

try:
    from config.settings import USER_AGENT, DEFAULT_TIMEOUT
except ImportError:
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    DEFAULT_TIMEOUT = 10

def assess_content_security_risk(found_content):
    """Assess security risk of discovered content"""
    findings = []
    severity = "I"
    
    if not found_content:
        return findings, severity
    
    # Critical paths that indicate serious security issues
    critical_paths = [
        '/.env', '/.git', '/config', '/backup', '/backups', 
        '/phpinfo.php', '/info.php', '/test.php', '/.DS_Store'
    ]
    
    # High-risk administrative paths
    high_risk_paths = [
        '/admin', '/administrator', '/wp-admin', '/login', '/signin',
        '/dashboard', '/panel', '/control', '/manage', '/setup'
    ]
    
    # API and development paths
    api_paths = ['/api', '/v1', '/v2', '/rest', '/graphql']
    
    # Analyze findings
    critical_found = []
    high_risk_found = []
    api_found = []
    accessible_admin = []
    
    for item in found_content:
        path = item['path']
        status = item['status']
        
        # Check for critical exposures
        if any(critical_path in path for critical_path in critical_paths):
            critical_found.append(f"{path} [{status}]")
            
        # Check for admin panels
        elif any(admin_path in path for admin_path in high_risk_paths):
            high_risk_found.append(f"{path} [{status}]")
            if status == 200:  # Directly accessible admin panel
                accessible_admin.append(path)
                
        # Check for API endpoints
        elif any(api_path in path for api_path in api_paths):
            api_found.append(f"{path} [{status}]")
    
    # Determine severity based on findings
    if critical_found:
        severity = "C"
        findings.append(f"Critical files exposed: {len(critical_found)} sensitive files accessible")
        for item in critical_found[:3]:  # Show first 3
            findings.append(f"Critical exposure: {item}")
            
    if accessible_admin:
        if severity != "C":
            severity = "H"
        findings.append(f"Admin panels accessible: {len(accessible_admin)} administrative interfaces")
        
    elif high_risk_found:
        if severity not in ["C", "H"]:
            severity = "H"
        findings.append(f"Administrative paths found: {len(high_risk_found)} admin-related endpoints")
    
    if api_found:
        if severity not in ["C", "H"]:
            severity = "W"
        findings.append(f"API endpoints discovered: {len(api_found)} API interfaces")
    
    # General exposure assessment
    total_accessible = len([item for item in found_content if item['status'] == 200])
    if total_accessible >= 10 and severity == "I":
        severity = "W"
        findings.append(f"High content exposure: {total_accessible} accessible paths")
    elif total_accessible >= 5 and severity == "I":
        findings.append(f"Moderate content exposure: {total_accessible} accessible paths")
    
    return findings, severity

def get_path_risk_level(path, status):
    """Determine risk level for individual paths"""
    # Critical paths
    critical_paths = ['/.env', '/.git', '/config', '/backup', '/backups', 
                     '/phpinfo.php', '/info.php', '/test.php', '/.DS_Store']
    
    # High-risk paths
    high_risk_paths = ['/admin', '/administrator', '/wp-admin', '/login', '/signin',
                      '/dashboard', '/panel', '/control', '/manage', '/setup']
    
    # API paths
    api_paths = ['/api', '/v1', '/v2', '/rest', '/graphql']
    
    if any(critical_path in path for critical_path in critical_paths):
        return "C"
    elif any(admin_path in path for admin_path in high_risk_paths):
        return "H" if status == 200 else "W"
    elif any(api_path in path for api_path in api_paths):
        return "W"
    elif status == 200:
        return "I"
    else:
        return "I"

def check_path(base_url, path, session):
    """Check if a path exists on the target"""
    try:
        url = urljoin(base_url, path)
        headers = {'User-Agent': USER_AGENT}
        
        response = session.get(url, headers=headers, timeout=5, allow_redirects=False)
        
        # Consider these status codes as "found"
        if response.status_code in [200, 301, 302, 403, 401]:
            content_type = response.headers.get('content-type', 'unknown').split(';')[0].strip()
            
            return {
                "path": path,
                "url": url,
                "status": response.status_code,
                "size": len(response.content),
                "type": content_type,
                "risk_level": get_path_risk_level(path, response.status_code)
            }
    except:
        pass
    return None

def get_comprehensive_wordlist():
    """Get comprehensive wordlist for content discovery"""
    return [
        # Administrative interfaces
        '/admin', '/administrator', '/wp-admin', '/login', '/signin',
        '/dashboard', '/panel', '/control', '/manage', '/console',
        
        # API endpoints
        '/api', '/v1', '/v2', '/v3', '/rest', '/graphql', '/swagger',
        '/api-docs', '/docs/api', '/openapi.json',
        
        # Backup and temporary files
        '/backup', '/backups', '/old', '/tmp', '/temp',
        '/archive', '/archives', '/dump', '/dumps',
        
        # Configuration files
        '/config', '/settings', '/setup', '/install',
        '/.env', '/.env.local', '/.env.production',
        '/wp-config.php', '/config.php', '/configuration.php',
        
        # Version control and development
        '/.git', '/.svn', '/.hg', '/.bzr',
        '/.git/config', '/.git/HEAD', '/.gitignore',
        
        # Information disclosure
        '/robots.txt', '/sitemap.xml', '/.well-known',
        '/phpinfo.php', '/info.php', '/test.php',
        '/.DS_Store', '/thumbs.db',
        
        # Status and monitoring
        '/status', '/health', '/ping', '/version', '/info',
        '/metrics', '/stats', '/monitor', '/check',
        
        # File uploads and media
        '/uploads', '/files', '/images', '/assets', '/media',
        '/documents', '/downloads', '/attachments',
        
        # Documentation and help
        '/docs', '/help', '/support', '/manual',
        '/readme', '/changelog', '/license',
        
        # Content management
        '/blog', '/forum', '/shop', '/store', '/cms',
        '/news', '/articles', '/posts',
        
        # Development and testing
        '/dev', '/test', '/staging', '/qa',
        '/debug', '/trace', '/log', '/logs',
        
        # Security-related
        '/security', '/auth', '/oauth', '/sso',
        '/cert', '/ssl', '/tls'
    ]

def discover_content(target, max_workers=10):
    """Discover hidden content and directories"""
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    wordlist = get_comprehensive_wordlist()
    found_content = []
    
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {
                executor.submit(check_path, target, path, session): path 
                for path in wordlist
            }
            
            for future in as_completed(future_to_path):
                result = future.result()
                if result:
                    found_content.append(result)
    
    return sorted(found_content, key=lambda x: (x['risk_level'], x['path']))

def main(target):
    """Main execution with clean output"""
    print(f"[I] Content Discovery - {target}")
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
        print("[I] Scanning common paths...")
        print()
        
        # Perform content discovery (Keep existing logic unchanged)
        found_content = discover_content(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # NEW: Prepare data for findings system
        scan_data = {
            "target": target,
            "found_paths": found_content,
            "total_paths_scanned": len(get_comprehensive_wordlist()),
            "paths_found": len(found_content),
            "scan_completed": True,
            "status": "SUCCESS"
        }
        
        # Add categorized findings for findings system
        if found_content:
            # Assess security risk
            security_findings, severity = assess_content_security_risk(found_content)
            
            # Categorize paths for findings evaluation
            critical_paths = [item for item in found_content if item['risk_level'] == 'C']
            admin_interfaces = [item for item in found_content if item['risk_level'] == 'H']
            sensitive_files = [item for item in found_content if any(keyword in item['path'] for keyword in ['.env', '.git', 'config', 'backup', 'phpinfo'])]
            
            scan_data.update({
                "critical_paths": critical_paths,
                "admin_interfaces": admin_interfaces, 
                "sensitive_files": sensitive_files,
                "security_findings": security_findings,
                "severity": severity
            })
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("content_discovery.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback for legacy mode
            has_issues = len(found_content) > 0 and any(item['risk_level'] in ['C', 'H'] for item in found_content)
            findings_result = {
                "success": not has_issues,
                "severity": severity if found_content else "I",
                "findings": [],
                "has_findings": has_issues
            }
        
        # Legacy output format when findings system not available
        if not FINDINGS_AVAILABLE and found_content:
            # Assess security risk
            security_findings, severity = assess_content_security_risk(found_content)
            
            print(f"[{severity}] CONTENT DISCOVERED: Found {len(found_content)} accessible paths")
            
            # Show security findings
            if security_findings:
                print(f"[{severity}] SECURITY ANALYSIS:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Group by risk level
            risk_groups = {'C': [], 'H': [], 'W': [], 'I': []}
            for item in found_content:
                risk_level = item['risk_level']
                risk_groups[risk_level].append(item)
            
            # Display critical and high-risk items first
            for risk_level in ['C', 'H', 'W', 'I']:
                if risk_groups[risk_level]:
                    files = risk_groups[risk_level]
                    risk_names = {'C': 'CRITICAL', 'H': 'HIGH RISK', 'W': 'WARNING', 'I': 'INFORMATIONAL'}
                    
                    print(f"[{risk_level}] {risk_names[risk_level]} PATHS ({len(files)}):")
                    for item in files[:10]:  # Show first 10 in each category
                        print(f"  [{risk_level}] {item['path']} [{item['status']}] ({item['type']})")
                    
                    if len(files) > 10:
                        print(f"  [{risk_level}] ... and {len(files) - 10} more paths")
                    print()
            
            # Status code summary
            status_summary = {}
            for item in found_content:
                status = item['status']
                status_summary[status] = status_summary.get(status, 0) + 1
            
            print("[I] STATUS CODE SUMMARY:")
            for status_code in sorted(status_summary.keys()):
                count = status_summary[status_code]
                status_name = {
                    200: "Accessible",
                    301: "Redirected", 
                    302: "Redirected",
                    401: "Requires Authentication",
                    403: "Forbidden"
                }.get(status_code, f"Status {status_code}")
                print(f"  [I] {status_code} ({status_name}): {count} paths")
        
        elif not FINDINGS_AVAILABLE and not found_content:
            print("[I] NO DATA: No accessible paths found")
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        
        # NEW: Return standardized format
        return {
            "status": "SUCCESS" if findings_result["success"] else "FAILED",
            "data": scan_data,                    # Your existing scan results
            "findings": findings_result,          # New findings data
            "execution_time": execution_time,
            "target": target
        }
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Discovery stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during content discovery")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("[E] ERROR: Connection error - target may be unreachable")
            status = "CONNECTION_ERROR"
        else:
            print(f"[E] ERROR: {error_msg}")
            status = "ERROR"
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        
        # NEW: Enhanced error handling with findings system
        if FINDINGS_AVAILABLE:
            findings_result = {
                "success": False,
                "severity": "E",
                "findings": [f"Scan error: {error_msg}"],
                "has_findings": True
            }
        else:
            findings_result = {
                "success": False,
                "severity": "E",
                "findings": [],
                "has_findings": False
            }
        
        return {
            "status": status, 
            "error": error_msg, 
            "execution_time": execution_time,
            "findings": findings_result,
            "target": target
        }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print("[E] ERROR: No target provided")
        print("Usage: python content_discovery.py <url_or_domain>")
        print("Example: python content_discovery.py example.com")
        sys.exit(1)