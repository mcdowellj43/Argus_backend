#!/usr/bin/env python3
"""
Improved Pastebin Monitoring Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
Note: This module uses free search methods and may require API keys for comprehensive monitoring
"""

import os
import sys
import requests
import re
from datetime import datetime
from urllib.parse import quote
import time

# Fix encoding issues for Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config.settings import USER_AGENT, DEFAULT_TIMEOUT, API_KEYS
    PASTEBIN_API_KEY = API_KEYS.get("PASTEBIN_API_KEY") if hasattr(API_KEYS, 'get') else None
    GOOGLE_API_KEY = API_KEYS.get("GOOGLE_API_KEY") if hasattr(API_KEYS, 'get') else None
    GOOGLE_CSE_ID = API_KEYS.get("GOOGLE_CSE_ID") if hasattr(API_KEYS, 'get') else None
except (ImportError, AttributeError):
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    DEFAULT_TIMEOUT = 30
    PASTEBIN_API_KEY = None
    GOOGLE_API_KEY = None
    GOOGLE_CSE_ID = None

def assess_paste_security_risk(results, patterns):
    """Assess security risk of found paste mentions"""
    findings = []
    severity = "I"
    
    google_results = results.get("google_search", {}).get("results", [])
    duckduckgo_results = results.get("duckduckgo_search", [])
    all_results = google_results + duckduckgo_results
    
    if not all_results:
        return findings, severity
    
    # Analyze each result for security implications
    high_risk_keywords = ['password', 'credential', 'database', 'dump', 'backup', 'config', 'secret', 'key']
    medium_risk_keywords = ['email', 'user', 'admin', 'login', 'token']
    
    for result in all_results:
        title = result.get('title', '').lower()
        snippet = result.get('snippet', '').lower()
        combined_text = f"{title} {snippet}"
        
        # Check for high-risk content
        high_risk_matches = [kw for kw in high_risk_keywords if kw in combined_text]
        medium_risk_matches = [kw for kw in medium_risk_keywords if kw in combined_text]
        
        if high_risk_matches:
            severity = "C"  # Critical
            findings.append(f"High-risk paste found: {result.get('url', 'Unknown URL')} (contains: {', '.join(high_risk_matches)})")
        elif medium_risk_matches:
            if severity not in ["C"]:
                severity = "W"  # Warning
            findings.append(f"Potentially sensitive paste: {result.get('url', 'Unknown URL')} (contains: {', '.join(medium_risk_matches)})")
        else:
            if severity not in ["C", "W"]:
                severity = "I"  # Info
            findings.append(f"Domain mention found: {result.get('url', 'Unknown URL')}")
    
    # Additional risk factors
    if len(all_results) >= 5:
        findings.append(f"High exposure: Domain mentioned in {len(all_results)} paste sites")
        severity = "H" if severity == "I" else severity
    
    return findings, severity

def search_google_for_pastes(domain, max_results=10):
    """Search Google for paste site results containing the domain"""
    if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
        return {"error": "Google API credentials required", "results": []}
    
    paste_sites = [
        'site:pastebin.com',
        'site:paste.ubuntu.com',
        'site:hastebin.com',
        'site:dpaste.de',
        'site:paste.ee',
        'site:justpaste.it'
    ]
    
    all_results = []
    
    for site in paste_sites:
        try:
            query = f'{site} "{domain}"'
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                'key': GOOGLE_API_KEY,
                'cx': GOOGLE_CSE_ID,
                'q': query,
                'num': min(max_results, 10)
            }
            
            response = requests.get(url, params=params, timeout=DEFAULT_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                
                for item in items:
                    all_results.append({
                        'title': item.get('title', ''),
                        'url': item.get('link', ''),
                        'snippet': item.get('snippet', ''),
                        'site': site.replace('site:', ''),
                        'display_url': item.get('displayLink', '')
                    })
            
            # Rate limiting
            time.sleep(0.5)
            
        except Exception:
            continue
    
    return {"results": all_results, "error": None}

def search_duckduckgo_pastes(domain):
    """Search DuckDuckGo for paste site results (free alternative)"""
    paste_sites = ['pastebin.com', 'hastebin.com', 'dpaste.de', 'paste.ee']
    found_results = []
    
    for site in paste_sites:
        try:
            # Use DuckDuckGo instant answer API (limited but free)
            query = f'site:{site} {domain}'
            url = f"https://api.duckduckgo.com/?q={quote(query)}&format=json&no_html=1&skip_disambig=1"
            
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                # DuckDuckGo instant answers are limited, but we can try
                abstract = data.get('Abstract', '')
                if abstract and domain in abstract:
                    found_results.append({
                        'site': site,
                        'query': query,
                        'snippet': abstract[:200],
                        'source': 'DuckDuckGo',
                        'note': 'Limited free search result',
                        'url': f"https://{site}/search?q={domain}"
                    })
            
            time.sleep(1)  # Rate limiting
            
        except Exception:
            continue
    
    return found_results

def check_common_paste_patterns(domain):
    """Check for common patterns that might indicate data leaks"""
    potential_indicators = []
    
    # Common patterns that might indicate data leaks
    leak_patterns = [
        f'{domain} database',
        f'{domain} dump',
        f'{domain} backup',
        f'{domain} credentials',
        f'{domain} passwords',
        f'{domain} users',
        f'{domain} emails',
        f'{domain} config',
        f'{domain} breach'
    ]
    
    # Email patterns for the domain
    email_patterns = [
        f'@{domain}',
        f'admin@{domain}',
        f'support@{domain}',
        f'info@{domain}',
        f'root@{domain}',
        f'contact@{domain}'
    ]
    
    # Combine all patterns
    all_patterns = leak_patterns + email_patterns
    
    return {
        "patterns_to_monitor": all_patterns,
        "leak_indicators": leak_patterns,
        "email_patterns": email_patterns,
        "monitoring_note": "These patterns should be monitored across paste sites"
    }

def simulate_paste_monitoring(domain):
    """Simulate comprehensive paste monitoring (placeholder for full implementation)"""
    # This would typically involve:
    # 1. Real-time monitoring of paste sites
    # 2. API integrations with multiple paste services
    # 3. Content analysis of found pastes
    # 4. Alert systems for new findings
    
    monitoring_sources = [
        "Pastebin.com",
        "GitHub Gists",
        "GitLab Snippets", 
        "Hastebin",
        "DPaste",
        "Paste.ee",
        "JustPaste.it",
        "Ubuntu Paste",
        "Various forums and leak sites"
    ]
    
    return {
        "sources_monitored": monitoring_sources,
        "monitoring_status": "Simulated - requires API integrations",
        "recommendation": "Implement real-time monitoring with proper API keys"
    }

def perform_paste_monitoring(target):
    """Perform paste site monitoring"""
    domain = target.replace('http://', '').replace('https://', '').split('/')[0]
    
    results = {
        "domain": domain,
        "google_search": {},
        "duckduckgo_search": [],
        "patterns": {},
        "monitoring_simulation": {},
        "api_status": {}
    }
    
    # Check API availability
    api_status = {
        "google_search_available": bool(GOOGLE_API_KEY and GOOGLE_CSE_ID),
        "pastebin_api_available": bool(PASTEBIN_API_KEY)
    }
    results["api_status"] = api_status
    
    # Google search for pastes
    if api_status["google_search_available"]:
        print("[I] Searching Google for paste site mentions...")
        results["google_search"] = search_google_for_pastes(domain)
    else:
        print("[I] Google API not configured, using alternative search...")
        results["duckduckgo_search"] = search_duckduckgo_pastes(domain)
    
    # Generate monitoring patterns
    print("[I] Generating monitoring patterns...")
    results["patterns"] = check_common_paste_patterns(domain)
    
    # Simulate comprehensive monitoring
    print("[I] Simulating comprehensive monitoring...")
    results["monitoring_simulation"] = simulate_paste_monitoring(domain)
    
    return results

def main(target):
    """Main execution with clean output"""
    print(f"[I] Pastebin Monitoring - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("[E] FAILED: Empty target provided")
            return {"status": "FAILED", "error": "Empty target"}
        
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        print(f"[I] Target: {domain}")
        
        # Check API status
        api_available = bool(GOOGLE_API_KEY and GOOGLE_CSE_ID)
        if not api_available:
            print("[W] LIMITED: No API keys configured - running in limited mode")
        
        print()
        
        # Perform paste monitoring
        results = perform_paste_monitoring(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Analyze results
        google_results = results.get("google_search", {}).get("results", [])
        duckduckgo_results = results.get("duckduckgo_search", [])
        total_findings = len(google_results) + len(duckduckgo_results)
        patterns = results.get("patterns", {})
        
        if total_findings > 0:
            # Assess security risk
            security_findings, severity = assess_paste_security_risk(results, patterns)
            
            print(f"[{severity}] PASTE MENTIONS: Found {total_findings} paste site mentions")
            
            # Display security analysis
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings[:5]:  # Show first 5
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display Google results
            if google_results:
                print(f"[W] Google Search Results ({len(google_results)}):")
                for i, result in enumerate(google_results[:5], 1):  # Show first 5
                    print(f"  [W] {i}. {result['title']}")
                    print(f"    - URL: {result['url']}")
                    if result['snippet']:
                        print(f"    - Preview: {result['snippet'][:100]}...")
                if len(google_results) > 5:
                    print(f"  [I] ... and {len(google_results) - 5} more results")
                print()
            
            # Display DuckDuckGo results
            if duckduckgo_results:
                print(f"[I] DuckDuckGo Results ({len(duckduckgo_results)}):")
                for i, result in enumerate(duckduckgo_results, 1):
                    print(f"  [I] {i}. {result['site']}: {result['snippet']}")
                print()
            
            # Show high-priority monitoring patterns
            leak_patterns = patterns.get("leak_indicators", [])
            if leak_patterns:
                print(f"[H] High-Priority Monitoring Patterns ({len(leak_patterns)}):")
                for pattern in leak_patterns[:5]:
                    print(f"  [H] \"{pattern}\"")
                print()
            
            print(f"[I] Execution time: {execution_time:.2f}s")
            
            return {
                "status": "SUCCESS",
                "data": results,
                "security_findings": security_findings,
                "severity": severity,
                "count": total_findings,
                "execution_time": execution_time
            }
        
        elif results.get("google_search", {}).get("error") or not api_available:
            print("[W] API LIMITATION: Limited search capabilities without API keys")
            print("[I] SETUP: Configure Google Custom Search API for comprehensive monitoring")
            
            # Still show monitoring recommendations
            patterns_list = patterns.get("patterns_to_monitor", [])
            if patterns_list:
                print()
                print(f"[I] Recommended Monitoring Patterns ({len(patterns_list)}):")
                for pattern in patterns_list[:5]:
                    print(f"  [I] \"{pattern}\"")
                print()
                
                # Show critical patterns to monitor
                leak_patterns = patterns.get("leak_indicators", [])
                if leak_patterns:
                    print(f"[H] Critical Data Leak Patterns ({len(leak_patterns)}):")
                    for pattern in leak_patterns:
                        print(f"  [H] \"{pattern}\"")
                    print()
            
            print(f"[I] Execution time: {execution_time:.2f}s")
            
            return {
                "status": "LIMITED",
                "data": results,
                "count": 0,
                "execution_time": execution_time,
                "note": "Limited functionality without API keys"
            }
        
        else:
            print("[S] NO FINDINGS: No paste site mentions found")
            
            # Still provide monitoring guidance
            patterns_list = patterns.get("patterns_to_monitor", [])
            if patterns_list:
                print(f"[I] Monitoring Setup: {len(patterns_list)} patterns should be monitored")
                print("[I] Consider setting up alerts for:")
                for pattern in patterns.get("leak_indicators", [])[:3]:
                    print(f"  [I] \"{pattern}\"")
            
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {
                "status": "NO_DATA",
                "data": results,
                "count": 0,
                "execution_time": execution_time
            }
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Monitoring stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during paste monitoring")
            status = "TIMEOUT"
        elif "quota" in error_msg.lower() or "limit" in error_msg.lower():
            print("[W] QUOTA: API quota exceeded")
            status = "QUOTA_EXCEEDED"
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
        print("Usage: python pastebin_monitoring.py <domain>")
        print("Example: python pastebin_monitoring.py example.com")
        print()
        print("Note: Enhanced functionality requires Google Custom Search API")
        sys.exit(1)