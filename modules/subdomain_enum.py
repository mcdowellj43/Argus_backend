#!/usr/bin/env python3
"""
Improved Subdomain Enumeration Module - Clean Output with Success/Failure Indicators
Fixed for Windows Unicode encoding issues
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
    if len(parts) < 2:  # Need at least domain.tld
        return False
        
    for part in parts:
        if not part or len(part) > 63:  # Each part max 63 chars
            return False
        # Each part must start/end with alphanumeric, can contain hyphens in middle
        if not part[0].isalnum() or not part[-1].isalnum():
            return False
        # Check all characters are valid
        for char in part:
            if not (char.isalnum() or char == '-'):
                return False
    
    return True

def assess_subdomain_security_risk(results):
    """Assess security risk of discovered subdomains"""
    findings = []
    severity = "I"
    
    all_subdomains = results.get("brute_force", []) + results.get("certificate_transparency_verified", [])
    
    if not all_subdomains:
        return findings, severity
    
    # High-risk subdomain patterns
    high_risk_patterns = ['admin', 'test', 'dev', 'staging', 'backup', 'database', 'db', 'api', 'vpn']
    medium_risk_patterns = ['ftp', 'ssh', 'mail', 'webmail', 'portal', 'dashboard', 'auth', 'login']
    
    high_risk_found = []
    medium_risk_found = []
    exposed_services = []
    
    for subdomain_info in all_subdomains:
        subdomain = subdomain_info.get("subdomain", "")
        subdomain_name = subdomain.split('.')[0].lower()
        
        # Check for high-risk patterns
        if any(pattern in subdomain_name for pattern in high_risk_patterns):
            high_risk_found.append(subdomain)
        elif any(pattern in subdomain_name for pattern in medium_risk_patterns):
            medium_risk_found.append(subdomain)
        
        # Check for exposed services
        http_status = subdomain_info.get("http_status")
        if http_status and http_status != 404:
            exposed_services.append(f"{subdomain} [{http_status}]")
    
    # Determine severity and findings
    if high_risk_found:
        severity = "C"
        findings.append(f"High-risk subdomains exposed: {len(high_risk_found)} critical subdomains")
        for subdomain in high_risk_found[:3]:  # Show first 3
            findings.append(f"Critical exposure: {subdomain}")
    
    if medium_risk_found and severity not in ["C"]:
        severity = "H"
        findings.append(f"Sensitive subdomains found: {len(medium_risk_found)} potentially sensitive")
    
    if len(all_subdomains) >= 20 and severity not in ["C", "H"]:
        severity = "W"
        findings.append(f"Large attack surface: {len(all_subdomains)} subdomains discovered")
    elif len(all_subdomains) >= 10 and severity == "I":
        severity = "W"
        findings.append(f"Moderate attack surface: {len(all_subdomains)} subdomains discovered")
    
    if exposed_services:
        if severity == "I":
            severity = "W"
        findings.append(f"Active web services: {len(exposed_services)} responding subdomains")
    
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
        future_to_subdomain = {
            executor.submit(dns_lookup_subdomain, subdomain, domain): subdomain 
            for subdomain in wordlist
        }
        
        for future in as_completed(future_to_subdomain):
            result = future.result()
            if result:
                found_subdomains.append(result)
    
    # HTTP verification phase
    if found_subdomains:
        print(f"[I] Verifying HTTP status for {len(found_subdomains)} subdomains...")
        
        verified_subdomains = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain_http, subdomain): subdomain 
                for subdomain in found_subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    verified_subdomains.append(result)
        
        return verified_subdomains
    
    return found_subdomains

def certificate_transparency_search(domain):
    """Search certificate transparency logs for subdomains"""
    subdomains = set()
    
    try:
        # Use crt.sh API
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                # Parse multiple names separated by newlines
                for name in name_value.split('\n'):
                    name = name.strip()
                    if name and name.endswith(f'.{domain}'):
                        # Remove wildcards
                        if name.startswith('*.'):
                            name = name[2:]
                        subdomains.add(name)
    except Exception:
        pass
    
    return list(subdomains)

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
    """Main execution with clean output"""
    print(f"[I] Subdomain Enumeration - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("[E] FAILED: Empty target provided")
            return {"status": "FAILED", "error": "Empty target"}
        
        domain = clean_domain_input(target)
        
        if not validate_domain(domain):
            print("[E] FAILED: Invalid domain format")
            return {"status": "FAILED", "error": "Invalid domain format"}
        
        print(f"[I] Target: {domain}")
        print()
        
        # Perform subdomain enumeration
        results = perform_subdomain_enumeration(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        summary = results["summary"]
        total_found = summary["active_subdomains"]
        
        if total_found > 0:
            # Assess security risk
            security_findings, severity = assess_subdomain_security_risk(results)
            
            print(f"[{severity}] SUBDOMAINS FOUND: {total_found} active subdomains discovered")
            
            # Display security analysis
            if security_findings:
                print(f"[{severity}] Security Risk Analysis:")
                for finding in security_findings:
                    print(f"  [{severity}] {finding}")
                print()
            
            # Display brute force results by risk level
            brute_force = results["brute_force"]
            if brute_force:
                # Group by risk level
                risk_groups = {"C": [], "H": [], "W": [], "I": []}
                for subdomain in brute_force:
                    risk = subdomain.get("risk_level", "I")
                    risk_groups[risk].append(subdomain)
                
                # Display critical subdomains first
                for risk_level in ["C", "H", "W", "I"]:
                    if risk_groups[risk_level]:
                        risk_names = {"C": "CRITICAL", "H": "HIGH RISK", "W": "WARNING", "I": "INFORMATIONAL"}
                        print(f"[{risk_level}] {risk_names[risk_level]} SUBDOMAINS ({len(risk_groups[risk_level])}):")
                        
                        for subdomain in risk_groups[risk_level][:5]:  # Show first 5 per category
                            status_info = ""
                            if subdomain.get("http_status"):
                                status_info = f" [{subdomain['http_status']}]"
                            if subdomain.get("title"):
                                status_info += f" - {subdomain['title'][:50]}"
                            
                            print(f"  [{risk_level}] {subdomain['subdomain']}{status_info}")
                            if len(subdomain.get("ip_addresses", [])) > 0:
                                print(f"    - IP: {', '.join(subdomain['ip_addresses'][:2])}")
                        
                        if len(risk_groups[risk_level]) > 5:
                            print(f"  [{risk_level}] ... and {len(risk_groups[risk_level]) - 5} more")
                        print()
            
            # Display certificate transparency results
            ct_results = results["certificate_transparency"]
            if ct_results:
                print(f"[I] CERTIFICATE TRANSPARENCY ({len(ct_results)}):")
                for subdomain in ct_results[:10]:
                    ct_risk = get_subdomain_risk_level(subdomain)
                    print(f"  [{ct_risk}] {subdomain}")
                if len(ct_results) > 10:
                    print(f"  [I] ... and {len(ct_results) - 10} more")
                print()
            
            # Display summary statistics
            print("[I] ENUMERATION SUMMARY:")
            print(f"  [I] Total unique subdomains: {summary['total_unique_subdomains']}")
            print(f"  [I] Active subdomains: {summary['active_subdomains']}")
            print(f"  [I] Brute force discovered: {summary['brute_force_found']}")
            print(f"  [I] Certificate transparency: {summary['certificate_transparency_found']}")
            print()
            print(f"[I] Execution time: {execution_time:.2f}s")
            
            return {
                "status": "SUCCESS",
                "data": results,
                "security_findings": security_findings,
                "severity": severity,
                "count": total_found,
                "execution_time": execution_time
            }
        else:
            print("[I] NO DATA: No subdomains found")
            print(f"[I] Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("[I] INTERRUPTED: Enumeration stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
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
        return {"status": status, "error": error_msg, "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        print("[E] ERROR: No target provided")
        print("Usage: python subdomain_enum.py <domain>")
        print("Example: python subdomain_enum.py example.com")
        sys.exit(1)