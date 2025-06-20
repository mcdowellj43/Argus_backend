#!/usr/bin/env python3
"""
Improved Pastebin Monitoring Module - Clean Output with Success/Failure Indicators
Note: This module uses free search methods and may require API keys for comprehensive monitoring
"""

import os
import sys
import requests
import re
from datetime import datetime
from urllib.parse import quote
import time

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import USER_AGENT, DEFAULT_TIMEOUT

# Try to import API keys
try:
    from config.settings import API_KEYS
    PASTEBIN_API_KEY = API_KEYS.get("PASTEBIN_API_KEY")
    GOOGLE_API_KEY = API_KEYS.get("GOOGLE_API_KEY")
    GOOGLE_CSE_ID = API_KEYS.get("GOOGLE_CSE_ID")
except (ImportError, AttributeError):
    PASTEBIN_API_KEY = None
    GOOGLE_API_KEY = None
    GOOGLE_CSE_ID = None

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
                        'note': 'Limited free search result'
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
        f'{domain} config'
    ]
    
    # Email patterns for the domain
    email_patterns = [
        f'@{domain}',
        f'admin@{domain}',
        f'support@{domain}',
        f'info@{domain}'
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
        print("🔍 Searching Google for paste site mentions...")
        results["google_search"] = search_google_for_pastes(domain)
    else:
        print("🔑 Google API not configured, using alternative search...")
        results["duckduckgo_search"] = search_duckduckgo_pastes(domain)
    
    # Generate monitoring patterns
    print("📋 Generating monitoring patterns...")
    results["patterns"] = check_common_paste_patterns(domain)
    
    # Simulate comprehensive monitoring
    print("🖥️ Simulating comprehensive monitoring...")
    results["monitoring_simulation"] = simulate_paste_monitoring(domain)
    
    return results

def main(target):
    """Main execution with clean output"""
    print(f"🔍 Pastebin Monitoring - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("❌ FAILED: Empty target provided")
            return {"status": "FAILED", "error": "Empty target"}
        
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        print(f"🎯 Target: {domain}")
        
        # Check API status
        api_available = bool(GOOGLE_API_KEY and GOOGLE_CSE_ID)
        if not api_available:
            print("🔑 LIMITED: No API keys configured - running in limited mode")
        
        print()
        
        # Perform paste monitoring
        results = perform_paste_monitoring(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Analyze results
        google_results = results.get("google_search", {}).get("results", [])
        duckduckgo_results = results.get("duckduckgo_search", [])
        total_findings = len(google_results) + len(duckduckgo_results)
        
        if total_findings > 0:
            print(f"⚠️  POTENTIAL LEAKS: Found {total_findings} paste site mentions")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Display Google results
            if google_results:
                print(f"🔍 Google Search Results ({len(google_results)}):")
                for result in google_results[:5]:  # Show first 5
                    print(f"   • {result['title']}")
                    print(f"     └─ {result['url']}")
                    if result['snippet']:
                        print(f"     └─ {result['snippet'][:100]}...")
                print()
            
            # Display DuckDuckGo results
            if duckduckgo_results:
                print(f"🦆 DuckDuckGo Results ({len(duckduckgo_results)}):")
                for result in duckduckgo_results:
                    print(f"   • {result['site']}: {result['snippet']}")
                print()
            
            # Show monitoring patterns
            patterns = results.get("patterns", {}).get("patterns_to_monitor", [])
            if patterns:
                print(f"📋 Recommended Monitoring Patterns ({len(patterns)}):")
                for pattern in patterns[:5]:
                    print(f"   • \"{pattern}\"")
                print()
            
            return {
                "status": "SUCCESS",
                "data": results,
                "count": total_findings,
                "execution_time": execution_time,
                "severity": "HIGH" if total_findings > 3 else "MEDIUM"
            }
        
        elif results.get("google_search", {}).get("error") or not api_available:
            print("🔑 API LIMITATION: Limited search capabilities without API keys")
            print("ℹ️  SETUP: Configure Google Custom Search API for comprehensive monitoring")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            
            # Still show monitoring recommendations
            patterns = results.get("patterns", {}).get("patterns_to_monitor", [])
            if patterns:
                print()
                print(f"📋 Recommended Monitoring Patterns ({len(patterns)}):")
                for pattern in patterns[:5]:
                    print(f"   • \"{pattern}\"")
            
            return {
                "status": "LIMITED",
                "data": results,
                "count": 0,
                "execution_time": execution_time,
                "note": "Limited functionality without API keys"
            }
        
        else:
            print("✅ NO FINDINGS: No paste site mentions found")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {
                "status": "NO_DATA",
                "data": results,
                "count": 0,
                "execution_time": execution_time
            }
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Monitoring stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("⏰ TIMEOUT: Request timeout during paste monitoring")
            status = "TIMEOUT"
        elif "quota" in error_msg.lower() or "limit" in error_msg.lower():
            print("📊 QUOTA: API quota exceeded")
            status = "QUOTA_EXCEEDED"
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
        print("Usage: python pastebin_monitoring.py <domain>")
        print("Example: python pastebin_monitoring.py example.com")
        print()
        print("Note: Enhanced functionality requires Google Custom Search API")
        sys.exit(1)