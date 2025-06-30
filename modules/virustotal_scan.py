#!/usr/bin/env python3
"""
Enhanced VirusTotal Scan Module - Clean Output with Centralized Binary Findings System
Note: This module requires a VirusTotal API key for functionality
"""

import os
import sys
import requests
import time
import hashlib
from datetime import datetime
from urllib.parse import urlparse

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# NEW: Import findings system
try:
    from config.findings_rules import evaluate_findings, display_findings_result
    FINDINGS_AVAILABLE = True
except ImportError:
    print("[W] Findings system not available - running in legacy mode")
    FINDINGS_AVAILABLE = False

from utils.util import clean_domain_input
from config.settings import DEFAULT_TIMEOUT

# Try to import API keys
try:
    from config.settings import API_KEYS
    VIRUSTOTAL_API_KEY = API_KEYS.get("VIRUSTOTAL_API_KEY")
except (ImportError, AttributeError):
    VIRUSTOTAL_API_KEY = None

def submit_url_scan(url):
    """Submit URL for scanning to VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key required", "scan_id": None}
    
    try:
        scan_url = "https://www.virustotal.com/api/v3/urls"
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {'url': url}
        
        response = requests.post(scan_url, headers=headers, data=data, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code == 200:
            result = response.json()
            # Extract scan ID from the response
            scan_id = result.get('data', {}).get('id')
            return {"scan_id": scan_id, "error": None}
        elif response.status_code == 401:
            return {"error": "Invalid VirusTotal API key", "scan_id": None}
        elif response.status_code == 429:
            return {"error": "API rate limit exceeded", "scan_id": None}
        else:
            return {"error": f"API error: {response.status_code}", "scan_id": None}
            
    except requests.exceptions.Timeout:
        return {"error": "Request timeout", "scan_id": None}
    except Exception as e:
        return {"error": str(e), "scan_id": None}

def get_url_report(url_id):
    """Get URL scan report from VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key required", "data": None}
    
    try:
        report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        
        response = requests.get(report_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code == 200:
            return {"data": response.json(), "error": None}
        elif response.status_code == 401:
            return {"error": "Invalid VirusTotal API key", "data": None}
        elif response.status_code == 404:
            return {"error": "Scan not found", "data": None}
        elif response.status_code == 429:
            return {"error": "API rate limit exceeded", "data": None}
        else:
            return {"error": f"API error: {response.status_code}", "data": None}
            
    except requests.exceptions.Timeout:
        return {"error": "Request timeout", "data": None}
    except Exception as e:
        return {"error": str(e), "data": None}

def get_domain_report(domain):
    """Get domain report from VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key required", "data": None}
    
    try:
        domain_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        
        response = requests.get(domain_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code == 200:
            return {"data": response.json(), "error": None}
        elif response.status_code == 401:
            return {"error": "Invalid VirusTotal API key", "data": None}
        elif response.status_code == 404:
            return {"error": "Domain not found in VirusTotal database", "data": None}
        elif response.status_code == 429:
            return {"error": "API rate limit exceeded", "data": None}
        else:
            return {"error": f"API error: {response.status_code}", "data": None}
            
    except requests.exceptions.Timeout:
        return {"error": "Request timeout", "data": None}
    except Exception as e:
        return {"error": str(e), "data": None}

def parse_scan_results(scan_data):
    """Parse VirusTotal scan results"""
    if not scan_data:
        return {}
    
    attributes = scan_data.get('data', {}).get('attributes', {})
    stats = attributes.get('stats', {})
    
    parsed = {
        "scan_date": attributes.get('date'),
        "total_engines": stats.get('harmless', 0) + stats.get('malicious', 0) + 
                       stats.get('suspicious', 0) + stats.get('undetected', 0),
        "malicious": stats.get('malicious', 0),
        "suspicious": stats.get('suspicious', 0),
        "harmless": stats.get('harmless', 0),
        "undetected": stats.get('undetected', 0),
        "detection_ratio": f"{stats.get('malicious', 0)}/{stats.get('malicious', 0) + stats.get('harmless', 0) + stats.get('suspicious', 0) + stats.get('undetected', 0)}",
        "scan_results": {}
    }
    
    # Parse individual engine results
    results = attributes.get('results', {})
    for engine, result in results.items():
        if result.get('result') and result.get('result') != 'clean':
            parsed["scan_results"][engine] = {
                "result": result.get('result'),
                "category": result.get('category'),
                "engine_version": result.get('engine_version')
            }
    
    return parsed

def parse_domain_data(domain_data):
    """Parse VirusTotal domain data"""
    if not domain_data:
        return {}
    
    attributes = domain_data.get('data', {}).get('attributes', {})
    
    parsed = {
        "domain": attributes.get('id'),
        "reputation": attributes.get('reputation', 0),
        "last_analysis_stats": attributes.get('last_analysis_stats', {}),
        "categories": attributes.get('categories', {}),
        "last_analysis_date": attributes.get('last_analysis_date'),
        "creation_date": attributes.get('creation_date'),
        "last_modification_date": attributes.get('last_modification_date'),
        "registrar": attributes.get('registrar'),
        "whois": attributes.get('whois', '')[:500] if attributes.get('whois') else '',  # Truncate
        "tags": attributes.get('tags', [])
    }
    
    return parsed

def wait_for_scan_completion(scan_id, max_wait_time=300):
    """Wait for URL scan to complete"""
    print("[I] Waiting for scan to complete...")
    
    wait_time = 0
    while wait_time < max_wait_time:
        time.sleep(15)  # Wait 15 seconds between checks
        wait_time += 15
        
        report = get_url_report(scan_id)
        if report["error"]:
            return report
        
        status = report["data"].get("data", {}).get("attributes", {}).get("status")
        
        if status == "completed":
            return report
        
        print(f"[I] Still scanning... ({wait_time}s elapsed)")
    
    return {"error": "Scan timeout - analysis took too long", "data": None}

def perform_virustotal_scan(target):
    """Perform comprehensive VirusTotal scan"""
    results = {
        "target": target,
        "url_scan": {},
        "domain_analysis": {},
        "summary": {},
        "scan_completed": True,
        "status": "SUCCESS"
    }
    
    # Determine if target is URL or domain
    if target.startswith(('http://', 'https://')):
        # URL scan
        print("[I] Submitting URL for scanning...")
        scan_result = submit_url_scan(target)
        
        if scan_result["error"]:
            results["url_scan"] = {"error": scan_result["error"]}
        else:
            # Wait for completion and get report
            scan_id = scan_result["scan_id"]
            report = wait_for_scan_completion(scan_id)
            
            if report["error"]:
                results["url_scan"] = {"error": report["error"]}
            else:
                results["url_scan"] = parse_scan_results(report["data"])
        
        # Extract domain for domain analysis
        domain = urlparse(target).netloc
    else:
        domain = clean_domain_input(target)
    
    # Domain analysis
    print(f"[I] Analyzing domain: {domain}")
    domain_result = get_domain_report(domain)
    
    if domain_result["error"]:
        results["domain_analysis"] = {"error": domain_result["error"]}
    else:
        results["domain_analysis"] = parse_domain_data(domain_result["data"])
    
    # Create summary for findings system
    url_malicious = results["url_scan"].get("malicious", 0)
    url_suspicious = results["url_scan"].get("suspicious", 0)
    domain_malicious = results["domain_analysis"].get("last_analysis_stats", {}).get("malicious", 0)
    domain_suspicious = results["domain_analysis"].get("last_analysis_stats", {}).get("suspicious", 0)
    
    # NEW: Add required fields for findings evaluation
    results["malicious_count"] = url_malicious + domain_malicious
    results["suspicious_count"] = url_suspicious + domain_suspicious
    results["total_threats"] = results["malicious_count"] + results["suspicious_count"]
    results["reputation_score"] = results["domain_analysis"].get("reputation", 0)
    
    results["summary"] = {
        "url_threats_detected": url_malicious + url_suspicious,
        "domain_threats_detected": domain_malicious + domain_suspicious,
        "overall_risk": "HIGH" if (url_malicious > 0 or domain_malicious > 0) else 
                       "MEDIUM" if (url_suspicious > 0 or domain_suspicious > 0) else "LOW",
        "reputation_score": results["reputation_score"]
    }
    
    return results

def main(target):
    """Main execution with clean output"""
    print(f"[I] VirusTotal Scan - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("[E] FAILED: Empty target provided")
            return {"status": "FAILED", "error": "Empty target"}
        
        # Check API key availability
        if not VIRUSTOTAL_API_KEY:
            print("[E] ERROR: VirusTotal API key not configured")
            print("[I] SETUP: Configure VIRUSTOTAL_API_KEY in config/settings.py")
            return {"status": "API_ERROR", "error": "API key required"}
        
        print(f"[I] Target: {target}")
        print()
        
        # Perform VirusTotal scan (Keep existing logic unchanged)
        scan_data = perform_virustotal_scan(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("virustotal_scan.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback for legacy mode
            total_threats = scan_data.get("total_threats", 0)
            findings_result = {
                "success": total_threats == 0,
                "severity": "C" if scan_data.get("malicious_count", 0) > 0 else "W" if scan_data.get("suspicious_count", 0) > 0 else "I",
                "findings": [],
                "has_findings": total_threats > 0
            }
        
        # Legacy output format when findings system not available
        if not FINDINGS_AVAILABLE:
            # Analyze results for legacy display
            summary = scan_data["summary"]
            url_threats = summary["url_threats_detected"]
            domain_threats = summary["domain_threats_detected"]
            total_threats = url_threats + domain_threats
            overall_risk = summary["overall_risk"]
            
            if total_threats > 0:
                print(f"[W] THREATS DETECTED: Found {total_threats} security threats")
                print(f"[I] Risk Level: {overall_risk}")
                print(f"[I] Execution time: {execution_time:.2f}s")
                print()
                
                # Display URL scan results
                url_scan = scan_data.get("url_scan", {})
                if not url_scan.get("error") and url_scan.get("malicious", 0) > 0:
                    print(f"[I] URL Scan Results:")
                    print(f"   Detection Ratio: {url_scan.get('detection_ratio', 'N/A')}")
                    print(f"   Malicious: {url_scan.get('malicious', 0)}")
                    print(f"   Suspicious: {url_scan.get('suspicious', 0)}")
                    print(f"   Total Engines: {url_scan.get('total_engines', 0)}")
                    
                    # Show detected threats
                    scan_results = url_scan.get("scan_results", {})
                    if scan_results:
                        print(f"   Detected Threats:")
                        for engine, detection in list(scan_results.items())[:5]:  # Show first 5
                            print(f"     - {engine}: {detection.get('result', 'Unknown')}")
                    print()
                
                # Display domain analysis results
                domain_analysis = scan_data.get("domain_analysis", {})
                if not domain_analysis.get("error"):
                    stats = domain_analysis.get("last_analysis_stats", {})
                    if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                        print(f"[I] Domain Analysis:")
                        print(f"   Reputation Score: {domain_analysis.get('reputation', 0)}")
                        print(f"   Malicious: {stats.get('malicious', 0)}")
                        print(f"   Suspicious: {stats.get('suspicious', 0)}")
                        print(f"   Harmless: {stats.get('harmless', 0)}")
                        
                        # Show categories if available
                        categories = domain_analysis.get("categories", {})
                        if categories:
                            category_list = list(categories.values())[:3]  # Show first 3
                            print(f"   Categories: {', '.join(category_list)}")
                        
                        # Show tags if available
                        tags = domain_analysis.get("tags", [])
                        if tags:
                            print(f"   Tags: {', '.join(tags[:5])}")  # Show first 5
                    print()
            
            elif scan_data.get("url_scan", {}).get("error") and scan_data.get("domain_analysis", {}).get("error"):
                # Both scans failed
                url_error = scan_data["url_scan"].get("error", "")
                domain_error = scan_data["domain_analysis"].get("error", "")
                
                if "API key" in url_error or "API key" in domain_error:
                    print("[E] API ERROR: Invalid VirusTotal API key")
                elif "rate limit" in url_error.lower() or "rate limit" in domain_error.lower():
                    print("[W] RATE LIMIT: VirusTotal API rate limit exceeded")
                else:
                    print(f"[E] ERROR: Scan failed")
                    print(f"   URL Error: {url_error}")
                    print(f"   Domain Error: {domain_error}")
                
                print(f"[I] Execution time: {execution_time:.2f}s")
            
            else:
                print("[S] CLEAN: No security threats detected")
                print(f"[I] Risk Level: {overall_risk}")
                print(f"[I] Execution time: {execution_time:.2f}s")
                print()
                
                # Show clean scan details
                url_scan = scan_data.get("url_scan", {})
                if not url_scan.get("error"):
                    print(f"[I] URL Scan: Clean ({url_scan.get('detection_ratio', 'N/A')})")
                
                domain_analysis = scan_data.get("domain_analysis", {})
                if not domain_analysis.get("error"):
                    reputation = domain_analysis.get("reputation", 0)
                    print(f"[I] Domain Reputation: {reputation}")
                    
                    stats = domain_analysis.get("last_analysis_stats", {})
                    if stats:
                        print(f"[I] Last Analysis: {stats.get('harmless', 0)} harmless, {stats.get('undetected', 0)} undetected")
        
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
        print("[I] INTERRUPTED: Scan stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during VirusTotal scan")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("[E] ERROR: Connection error during API requests")
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
        print("Usage: python virustotal_scan.py <url_or_domain>")
        print("Example: python virustotal_scan.py https://example.com")
        print("Example: python virustotal_scan.py example.com")
        print()
        print("Note: Requires VirusTotal API key")
        sys.exit(1)