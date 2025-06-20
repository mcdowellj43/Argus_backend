#!/usr/bin/env python3
"""
Improved Content Discovery Module - Clean Output with Success/Failure Indicators
"""

import os
import sys
import requests
from datetime import datetime
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import USER_AGENT, DEFAULT_TIMEOUT

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
                "type": content_type
            }
    except:
        pass
    return None

def discover_content(target, max_workers=10):
    """Discover hidden content and directories"""
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Common paths to check
    wordlist = [
        '/admin', '/administrator', '/wp-admin', '/login', '/signin',
        '/dashboard', '/panel', '/control', '/manage',
        '/api', '/v1', '/v2', '/rest', '/graphql',
        '/backup', '/backups', '/old', '/tmp',
        '/config', '/settings', '/setup',
        '/robots.txt', '/sitemap.xml', '/.well-known',
        '/.env', '/.git', '/.svn', '/.DS_Store',
        '/phpinfo.php', '/info.php', '/test.php',
        '/status', '/health', '/ping', '/version',
        '/uploads', '/files', '/images', '/assets',
        '/docs', '/help', '/support',
        '/blog', '/forum', '/shop', '/store'
    ]
    
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
    
    return sorted(found_content, key=lambda x: x['path'])

def main(target):
    """Main execution with clean output"""
    print(f"🔍 Content Discovery - {target}")
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
        print("🔍 Scanning common paths...")
        print()
        
        # Perform content discovery
        found_content = discover_content(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        if found_content:
            print(f"✅ SUCCESS: Found {len(found_content)} accessible paths")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Group by status code for better display
            status_groups = {}
            for item in found_content:
                status = item['status']
                if status not in status_groups:
                    status_groups[status] = []
                status_groups[status].append(item)
            
            # Display results grouped by status
            for status_code in sorted(status_groups.keys()):
                items = status_groups[status_code]
                status_name = {
                    200: "Accessible",
                    301: "Redirected", 
                    302: "Redirected",
                    401: "Requires Auth",
                    403: "Forbidden"
                }.get(status_code, f"Status {status_code}")
                
                print(f"📁 {status_name} ({status_code}) - {len(items)} items:")
                for item in items:
                    size_str = f"{item['size']} bytes" if item['size'] > 0 else "empty"
                    print(f"   • {item['path']} ({size_str}, {item['type']})")
                print()
            
            return {
                "status": "SUCCESS",
                "data": found_content,
                "count": len(found_content),
                "execution_time": execution_time
            }
        else:
            print("ℹ️  NO DATA: No accessible paths found")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Discovery stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("⏰ TIMEOUT: Request timeout during content discovery")
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
        print("Usage: python content_discovery.py <url_or_domain>")
        print("Example: python content_discovery.py example.com")
        sys.exit(1)