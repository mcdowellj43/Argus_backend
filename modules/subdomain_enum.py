#!/usr/bin/env python3
"""
Improved Subdomain Enumeration Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
UPDATED: Integrated with centralized findings system
"""

import os
import sys
import dns.resolver
import dns.exception
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

# Fix encoding issues for Windows
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.util import clean_domain_input
    from config.settings import USER_AGENT, DEFAULT_TIMEOUT
except ImportError:
    # Fallback implementations
    def clean_domain_input(domain):
        """Clean domain input"""
        if not domain:
            return ""
        domain = domain.strip().lower()
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.replace('www.', '')
        if '/' in domain:
            domain = domain.split('/')[0]
        return domain
    
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    DEFAULT_TIMEOUT = 10

# NEW: Import findings system
try:
    from config.findings_rules import evaluate_findings, display_findings_result
    FINDINGS_AVAILABLE = True
except ImportError:
    print("[W] Findings system not available - running in legacy mode")
    FINDINGS_AVAILABLE = False

# Use our own working validation function
def validate_domain(domain):
    """Proper domain validation that actually works"""
    if not domain or len(domain) < 3 or len(domain) > 255:
        return False
    
    # Check for obvious invalid patterns
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    if domain.startswith('-') or domain.endswith('-'):
        return False
    
    # Split into parts and validate each
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not part.replace('-', '').isalnum():
            return False
    
    return True

def assess_subdomain_security_risk(results):
    """Assess security risk level of subdomain findings"""
    findings = []
    severity = "I"
    
    brute_force_results = results.get("brute_force", [])
    ct_results = results.get("certificate_transparency", [])
    summary = results.get("summary", {})
    
    total_subdomains = summary.get("total_unique_subdomains", 0)
    active_subdomains = summary.get("active_subdomains", 0)
    
    if not total_subdomains:
        return findings, severity
    
    # Analyze risk-level distribution
    high_risk_subdomains = []
    critical_risk_subdomains = []
    exposed_services = []
    
    for subdomain_info in brute_force_results:
        risk_level = subdomain_info.get("risk_level", "I")
        subdomain_name = subdomain_info.get("subdomain", "")
        
        if risk_level == "C":
            critical_risk_subdomains.append(subdomain_name)
        elif risk_level == "H":
            high_risk_subdomains.append(subdomain_name)
        
        # Check for exposed services
        if subdomain_info.get("http_status"):
            exposed_services.append(subdomain_name)
    
    # Critical findings
    if critical_risk_subdomains:
        severity = "H"
        findings.append(f"High-risk subdomains found: {critical_risk_subdomains[:3]}")
        if len(critical_risk_subdomains) > 3:
            findings.append(f"Additional {len(critical_risk_subdomains) - 3} critical subdomains discovered")
    
    # High-risk findings
    if high_risk_subdomains:
        if severity == "I":
            severity = "W"
        findings.append(f"Administrative subdomains detected: {len(high_risk_subdomains)} found")
    
    # Large attack surface
    if total_subdomains >= 20 and severity not in ["C", "H"]:
        severity = "W"
        findings.append(f"Large attack surface: {total_subdomains} subdomains discovered")
    elif total_subdomains >= 10 and severity == "I":
        severity = "W"
        findings.append(f"Moderate attack surface: {total_subdomains} subdomains discovered")
    
    # Active services
    if exposed_services:
        if severity == "I":
            severity = "W"
        findings.append(f"Active web services: {len(exposed_services)} responding subdomains")
    
    # Certificate transparency exposure
    if ct_results and len(ct_results) > 10:
        findings.append(f"High CT log exposure: {len(ct_results)} subdomains in certificate logs")
        if severity == "I":
            severity = "W"
    
    return findings, severity

def get_common_subdomains():
    """Get list of common subdomain prefixes"""
    return [
        # Common service subdomains
        'www', 'mail', 'email', 'webmail', 'smtp', 'pop', 'imap',
        'api', 'app', 'mobile', 'admin', 'portal', 'dashboard',
        'blog', 'forum', 'shop', 'store', 'support', 'help',
        
        # Development/staging
        'dev', 'test', 'staging', 'qa', 'uat', 'demo', 'beta',
        'alpha', 'preview', 'temp', 'tmp',
        
        # Infrastructure
        'cdn', 'static', 'assets', 'img', 'images', 'js', 'css',
        'files', 'download', 'uploads', 'media', 'content',
        
        # Services
        'ftp', 'sftp', 'ssh', 'vpn', 'remote', 'proxy',
        'dns', 'ns', 'ns1', 'ns2', 'mx', 'mx1', 'mx2',
        
        # Geographic/Regional
        'us', 'eu', 'asia', 'uk', 'ca', 'au', 'de', 'fr',
        'east', 'west', 'north', 'south',
        
        # Business units
        'sales', 'marketing', 'hr', 'finance', 'legal',
        'training', 'docs', 'wiki', 'kb', 'news',
        
        # Technical
        'db', 'database', 'backup', 'archive', 'logs',
        'monitor', 'status', 'health', 'metrics',
        'git', 'svn', 'jenkins', 'ci', 'cd',
        
        # Security
        'secure', 'ssl', 'vpn', 'firewall', 'gateway',
        'auth', 'sso', 'ldap', 'ad',
        
        # Cloud services
        'aws', 'azure', 'gcp', 'cloud', 's3', 'storage'
    ]

def get_subdomain_risk_level(subdomain):
    """Assess individual subdomain risk level"""
    subdomain_name = subdomain.split('.')[0].lower()
    
    critical_patterns = ['admin', 'root', 'administrator', 'test', 'dev', 'staging', 'backup', 'database', 'db']
    high_patterns = ['api', 'ftp', 'ssh', 'vpn', 'mail', 'webmail', 'portal', 'dashboard', 'auth', 'login']
    medium_patterns = ['support', 'help', 'blog', 'forum', 'shop', 'store']
    
    if any(pattern in subdomain_name for pattern in critical_patterns):
        return "C"
    elif any(pattern in subdomain_name for pattern in high_patterns):
        return "H"
    elif any(pattern in subdomain_name for pattern in medium_patterns):
        return "W"
    else:
        return "I"

def dns_lookup_subdomain(subdomain, domain):
    """Perform DNS lookup for a single subdomain"""
    full_domain = f"{subdomain}.{domain}"
    
    try:
        # Try A record lookup
        answers = dns.resolver.resolve(full_domain, 'A', lifetime=3)
        ip_addresses = [str(rdata) for rdata in answers]
        
        # Also try to get CNAME if available
        cname = None
        try:
            cname_answers = dns.resolver.resolve(full_domain, 'CNAME', lifetime=2)
            cname = str(cname_answers[0])
        except:
            pass
        
        return {
            "subdomain": full_domain,
            "ip_addresses": ip_addresses,
            "cname": cname,
            "status": "active",
            "risk_level": get_subdomain_risk_level(full_domain)
        }
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except dns.exception.DNSException:
        return None
    except Exception:
        return None

def check_subdomain_http(subdomain_info):
    """Check if subdomain responds to HTTP requests"""
    subdomain = subdomain_info["subdomain"]
    
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{subdomain}"
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
            
            subdomain_info.update({
                "http_status": response.status_code,
                "http_protocol": protocol,
                "server": response.headers.get('server', ''),
                "title": extract_title(response.text) if response.text else ''
            })
            return subdomain_info
            
        except requests.exceptions.RequestException:
            continue
    
    # No HTTP response
    subdomain_info.update({
        "http_status": None,
        "http_protocol": None,
        "server": '',
        "title": ''
    })
    return subdomain_info

def extract_title(html_content):
    """Extract title from HTML content"""
    try:
        import re
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()[:100]  # Limit length
    except:
        pass
    return ''

def brute_force_subdomains(domain, wordlist=None, max_workers=20):
    """Brute force subdomain enumeration"""
    if wordlist is None:
        wordlist = get_common_subdomains()
    
    found_subdomains = []
    
    # DNS enumeration phase
    print(f"[I] Testing {len(wordlist)} common subdomains...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_subdomain = {executor.submit(dns_lookup_subdomain, sub, domain): sub for sub in wordlist}
        
        for future in as_completed(future_to_subdomain):
            result = future.result()
            if result:
                found_subdomains.append(result)
    
    # HTTP checking phase
    print(f"[I] Checking HTTP responses for {len(found_subdomains)} active subdomains...")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {executor.submit(check_subdomain_http, sub): sub for sub in found_subdomains}
        
        updated_subdomains = []
        for future in as_completed(future_to_subdomain):
            result = future.result()
            if result:
                updated_subdomains.append(result)
    
    return updated_subdomains

def certificate_transparency_search(domain):
    """Search certificate transparency logs for subdomains"""
    subdomains = []
    
    try:
        # Use crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            certificates = response.json()
            subdomain_set = set()
            
            for cert in certificates:
                name_value = cert.get('name_value', '')
                for name in name_value.split('\n'):
                    name = name.strip()
                    if name and name.endswith(f'.{domain}'):
                        # Remove wildcards
                        if name.startswith('*.'):
                            name = name[2:]
                        subdomain_set.add(name)
            
            subdomains = list(subdomain_set)
    except Exception:
        pass
    
    return subdomains

def search_engine_enumeration(domain):
    """Use search engines to find subdomains (limited free approach)"""
    # This would typically use search engine APIs
    # For now, we'll return an empty list as comprehensive search engine
    # enumeration requires API keys and specialized tools
    return []

def perform_subdomain_enumeration(target):
    """Perform comprehensive subdomain enumeration"""
    domain = clean_domain_input(target)
    
    results = {
        "domain": domain,
        "brute_force": [],
        "certificate_transparency": [],
        "search_engines": [],
        "summary": {}
    }
    
    # Brute force enumeration
    print("[I] Starting brute force enumeration...")
    results["brute_force"] = brute_force_subdomains(domain)
    
    # Certificate transparency search
    print("[I] Searching certificate transparency logs...")
    results["certificate_transparency"] = certificate_transparency_search(domain)
    
    # Search engine enumeration (placeholder)
    print("[I] Performing search engine enumeration...")
    results["search_engines"] = search_engine_enumeration(domain)
    
    # Combine and deduplicate results
    all_subdomains = set()
    
    # Add brute force results
    for sub in results["brute_force"]:
        all_subdomains.add(sub["subdomain"])
    
    # Add CT log results
    for sub in results["certificate_transparency"]:
        all_subdomains.add(sub)
    
    # Add search engine results
    for sub in results["search_engines"]:
        all_subdomains.add(sub)
    
    # Verify CT and search engine findings
    ct_only_subdomains = []
    for subdomain in results["certificate_transparency"]:
        if subdomain not in [s["subdomain"] for s in results["brute_force"]]:
            # Verify this subdomain
            parts = subdomain.split('.')
            if len(parts) > 2:
                sub_prefix = parts[0]
                lookup_result = dns_lookup_subdomain(sub_prefix, domain)
                if lookup_result:
                    ct_only_subdomains.append(lookup_result)
    
    results["certificate_transparency_verified"] = ct_only_subdomains
    
    # Create summary
    total_found = len(all_subdomains)
    active_count = len(results["brute_force"]) + len(ct_only_subdomains)
    
    results["summary"] = {
        "total_unique_subdomains": total_found,
        "active_subdomains": active_count,
        "brute_force_found": len(results["brute_force"]),
        "certificate_transparency_found": len(results["certificate_transparency"]),
        "certificate_transparency_verified": len(ct_only_subdomains)
    }
    
    return results

def main(target):
    """Main execution with enhanced findings evaluation"""
    print(f"[I] Subdomain Enumeration Analysis - {target}")
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
        
        domain = clean_domain_input(target)
        
        if not validate_domain(domain):
            print("[E] FAILED: Invalid domain format")
            
            # Error findings for invalid domain
            error_findings = {
                "success": False,
                "severity": "I",
                "findings": ["Invalid domain format provided"],
                "has_findings": True,
                "category": "Input Error"
            }
            
            return {
                "status": "FAILED",
                "error": "Invalid domain format",
                "findings": error_findings,
                "execution_time": (datetime.now() - start_time).total_seconds()
            }
        
        print(f"[I] Target: {domain}")
        print()
        
        # Perform subdomain enumeration (your existing logic)
        results = perform_subdomain_enumeration(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Prepare scan data for findings evaluation
        summary = results["summary"]
        total_found = summary["total_unique_subdomains"]
        active_found = summary["active_subdomains"]
        
        scan_data = {
            "domain": domain,
            "subdomains": [sub["subdomain"] for sub in results["brute_force"]] + 
                         [sub["subdomain"] for sub in results.get("certificate_transparency_verified", [])],
            "total_subdomains": total_found,
            "active_subdomains": active_found,
            "brute_force_results": results["brute_force"],
            "certificate_transparency_results": results["certificate_transparency"],
            "status": "SUCCESS" if total_found > 0 else "NO_DATA",
            "scan_completed": True
        }
        
        if total_found > 0:
            # Assess security risk (keep existing logic)
            security_findings, severity = assess_subdomain_security_risk(results)
            
            print(f"[{severity}] SUBDOMAINS FOUND: Discovered {total_found} unique subdomains ({active_found} active)")
            
            # Display legacy security analysis
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display results by category (keep existing display)
            brute_force_results = results["brute_force"]
            if brute_force_results:
                print(f"[I] BRUTE FORCE RESULTS ({len(brute_force_results)}):")
                
                # Group by risk level
                risk_groups = {"C": [], "H": [], "W": [], "I": []}
                for sub in brute_force_results:
                    risk = sub.get("risk_level", "I")
                    risk_groups[risk].append(sub)
                
                # Display by risk level
                for risk_level in ["C", "H", "W", "I"]:
                    if risk_groups[risk_level]:
                        risk_names = {"C": "CRITICAL", "H": "HIGH RISK", "W": "WARNING", "I": "INFORMATIONAL"}
                        print(f"  [{risk_level}] {risk_names[risk_level]} ({len(risk_groups[risk_level])}):")
                        
                        for sub in risk_groups[risk_level][:5]:  # Show first 5
                            subdomain = sub["subdomain"]
                            ip_info = f" -> {sub['ip_addresses'][0]}" if sub.get('ip_addresses') else ""
                            http_info = f" (HTTP {sub['http_status']})" if sub.get('http_status') else ""
                            print(f"    [{risk_level}] {subdomain}{ip_info}{http_info}")
                        
                        if len(risk_groups[risk_level]) > 5:
                            print(f"    [I] ... and {len(risk_groups[risk_level]) - 5} more")
                print()
            
            # Display certificate transparency results
            ct_results = results["certificate_transparency"]
            if ct_results:
                print(f"[I] CERTIFICATE TRANSPARENCY ({len(ct_results)}):")
                for subdomain in ct_results[:10]:  # Show first 10
                    print(f"  [I] {subdomain}")
                if len(ct_results) > 10:
                    print(f"  [I] ... and {len(ct_results) - 10} more subdomains in CT logs")
                print()
            
            # Display summary
            print("[I] ENUMERATION SUMMARY:")
            print(f"  [I] Brute Force: {summary['brute_force_found']} active subdomains")
            print(f"  [I] Certificate Transparency: {summary['certificate_transparency_found']} total ({summary.get('certificate_transparency_verified', 0)} verified)")
            print(f"  [I] Total Unique: {summary['total_unique_subdomains']} subdomains")
        else:
            print("[I] NO DATA: No subdomains found")
            security_findings = []
            severity = "I"
        
        print()
        
        # NEW: Enhanced findings evaluation
        if FINDINGS_AVAILABLE:
            findings_result = evaluate_findings("subdomain_enum.py", scan_data)
            display_findings_result(scan_data, findings_result)
        else:
            # Fallback to basic assessment
            if total_found > 0:
                findings = security_findings if security_findings else [f"Discovered {total_found} subdomains"]
            else:
                findings = ["No subdomains discovered"]
            
            findings_result = {
                "success": total_found > 0,
                "severity": severity,
                "findings": findings,
                "has_findings": total_found > 0,
                "category": "Subdomain Analysis"
            }
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        print()
        
        # Return standardized format
        return {
            "status": "SUCCESS" if findings_result["success"] else "FAILED",
            "data": scan_data,
            "findings": findings_result,
            "execution_time": execution_time,
            "target": target,
            # Keep legacy fields for backward compatibility
            "count": total_found,
            "security_findings": security_findings,
            "severity": findings_result["severity"]
        }
        
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Enumeration stopped by user")
        
        interrupt_findings = {
            "success": False,
            "severity": "I",
            "findings": ["Subdomain enumeration interrupted by user"],
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
        
        # Classify error types
        if "timeout" in error_msg.lower():
            print("[T] TIMEOUT: Request timeout during enumeration")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("[E] ERROR: Connection error during DNS lookups")
            status = "CONNECTION_ERROR"
        else:
            print(f"[E] ERROR: {error_msg}")
            status = "ERROR"
        
        print(f"[I] Execution time: {execution_time:.2f}s")
        
        # Error findings
        error_findings = {
            "success": False,
            "severity": "I",
            "findings": [f"Subdomain enumeration failed: {error_msg}"],
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
        print("Usage: python subdomain_enum.py <domain>")
        print("Example: python subdomain_enum.py example.com")
        sys.exit(1)