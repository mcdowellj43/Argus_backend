#!/usr/bin/env python3
"""
Improved Pastebin Monitoring Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
UPDATED: Integrated with centralized findings system
"""

import os
import sys
import requests
import time
from datetime import datetime

# Fix encoding issues for Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config.settings import DEFAULT_TIMEOUT, API_KEYS
    GOOGLE_API_KEY = API_KEYS.get("GOOGLE_API_KEY") if hasattr(API_KEYS, 'get') else None
    GOOGLE_CSE_ID = API_KEYS.get("GOOGLE_CSE_ID") if hasattr(API_KEYS, 'get') else None
    PASTEBIN_API_KEY = API_KEYS.get("PASTEBIN_API_KEY") if hasattr(API_KEYS, 'get') else None
except (ImportError, AttributeError):
    DEFAULT_TIMEOUT = 30
    GOOGLE_API_KEY = None
    GOOGLE_CSE_ID = None
    PASTEBIN_API_KEY = None

# NEW: Import findings system
try:
    from config.findings_rules import evaluate_findings, display_findings_result
    FINDINGS_AVAILABLE = True
except ImportError:
    print("[W] Findings system not available - running in legacy mode")
    FINDINGS_AVAILABLE = False

def assess_paste_security_risk(results, patterns):
    """Assess security risk level of paste findings"""
    findings = []
    severity = "I"
    
    # Combine all results from different search methods
    google_results = results.get("google_search", {}).get("results", [])
    duckduckgo_results = results.get("duckduckgo_search", [])
    all_results = google_results + duckduckgo_results
    
    if not all_results:
        return findings, severity
    
    # Risk keywords for content analysis
    high_risk_keywords = ['password', 'credential', 'secret', 'key', 'dump', 'database', 'breach']
    medium_risk_keywords = ['config', 'backup', 'log', 'api']
    risk_keywords = ['email', 'user', 'admin', 'login', 'token']
    
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
            query = f'{domain} {site}'
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                'key': GOOGLE_API_KEY,
                'cx': GOOGLE_CSE_ID,
                'q': query,
                'num': min(10, max_results)
            }
            
            response = requests.get(url, params=params, timeout=DEFAULT_TIMEOUT)
            data = response.json()
            
            if 'items' in data:
                for item in data['items']:
                    all_results.append({
                        'title': item.get('title', ''),
                        'url': item.get('link', ''),
                        'snippet': item.get('snippet', ''),
                        'source': 'Google',
                        'site': site.replace('site:', '')
                    })
            
            time.sleep(1)  # Rate limiting
            
        except Exception:
            continue
    
    return {"results": all_results[:max_results], "error": None}

def search_duckduckgo_pastes(domain):
    """Search DuckDuckGo for paste mentions (fallback method)"""
    paste_sites = ['pastebin.com', 'paste.ubuntu.com', 'hastebin.com', 'dpaste.de']
    found_results = []
    
    for site in paste_sites:
        try:
            query = f'{domain} site:{site}'
            url = "https://api.duckduckgo.com/"
            params = {
                'q': query,
                'format': 'json',
                'no_redirect': '1',
                'no_html': '1',
                'skip_disambig': '1'
            }
            
            response = requests.get(url, params=params, timeout=5)
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
    """Main execution with enhanced findings evaluation"""
    print(f"[I] Pastebin Monitoring Analysis - {target}")
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
        
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        print(f"[I] Target: {domain}")
        
        # Check API status
        api_available = bool(GOOGLE_API_KEY and GOOGLE_CSE_ID)
        if not api_available:
            print("[W] LIMITED: No API keys configured - running in limited mode")
        
        print()
        
        # Perform paste monitoring (your existing logic)
        results = perform_paste_monitoring(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Prepare scan data for findings evaluation
        google_results = results.get("google_search", {}).get("results", [])
        duckduckgo_results = results.get("duckduckgo_search", [])
        total_findings = len(google_results) + len(duckduckgo_results)
        patterns = results.get("patterns", {})
        
        scan_data = {
            "domain": domain,
            "pastes_found": google_results + duckduckgo_results,
            "total_pastes": total_findings,
            "google_results": len(google_results),
            "duckduckgo_results": len(duckduckgo_results),
            "api_available": api_available,
            "monitoring_patterns": patterns.get("patterns_to_monitor", []),
            "scan_completed": True
        }
        
        if total_findings > 0:
            # Assess security risk (keep existing logic)
            security_findings, severity = assess_paste_security_risk(results, patterns)
            
            print(f"[{severity}] PASTE MENTIONS: Found {total_findings} paste site mentions")
            
            # Display legacy security analysis
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings[:5]:  # Show first 5
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display Google results (keep existing display)
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
                    print(f"  [I] {i}. {result.get('site', 'Unknown site')}")
                    print(f"    - Query: {result.get('query', 'N/A')}")
                    print(f"    - Note: {result.get('note', 'N/A')}")
                print()
            
            # Display monitoring recommendations
            print("[I] Monitoring Recommendations:")
            print(f"  [I] Monitor {len(patterns.get('patterns_to_monitor', []))} specific patterns")
            print(f"  [I] Set up alerts for new paste mentions")
            print(f"  [I] Review {len(patterns.get('leak_indicators', []))} high-risk keywords")
        else:
            print("[S] CLEAN: No paste site mentions found")
            security_findings = []
            severity = "I"
        
        print()
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("pastebin_monitoring.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            if total_findings > 0:
                findings = security_findings if security_findings else [f"Found {total_findings} paste mentions"]
            else:
                findings = ["No paste site mentions detected"]
            
            findings_result = {
                "success": True,  # Scan completed successfully
                "severity": severity,
                "findings": findings,
                "has_findings": total_findings > 0,
                "category": "Paste Site Analysis"
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
            "count": total_findings,
            "security_findings": security_findings,
            "severity": findings_result["severity"]
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Monitoring stopped by user")
        
        interrupt_findings = {
            "success": False,
            "severity": "I",
            "findings": ["Paste monitoring interrupted by user"],
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
            print("[T] TIMEOUT: Request timeout during paste monitoring")
            status = "TIMEOUT"
        elif "quota" in error_msg.lower() or "limit" in error_msg.lower():
            print("[W] QUOTA: API quota exceeded")
            status = "QUOTA_EXCEEDED"
        else:
            print(f"[E] ERROR: {error_msg}")
            status = "ERROR"
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        
        # Error findings
        error_findings = {
            "success": False,
            "severity": "I",
            "findings": [f"Paste monitoring failed: {error_msg}"],
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
        print("Usage: python pastebin_monitoring.py <domain>")
        print("Example: python pastebin_monitoring.py example.com")
        print()
        print("Note: Enhanced functionality requires Google Custom Search API")
        sys.exit(1)