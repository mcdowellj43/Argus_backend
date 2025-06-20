#!/usr/bin/env python3
"""
Improved Subdomain Enumeration Module - Clean Output with Success/Failure Indicators
"""

import os
import sys
import dns.resolver
import dns.exception
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain
from config.settings import USER_AGENT, DEFAULT_TIMEOUT

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
            "status": "active"
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
    print(f"🔍 Testing {len(wordlist)} common subdomains...")
    
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
        print(f"🌐 Verifying HTTP status for {len(found_subdomains)} subdomains...")
        
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
    print("🚀 Starting brute force enumeration...")
    results["brute_force"] = brute_force_subdomains(domain)
    
    # Certificate transparency search
    print("🔍 Searching certificate transparency logs...")
    results["certificate_transparency"] = certificate_transparency_search(domain)
    
    # Search engine enumeration (placeholder)
    print("🔎 Performing search engine enumeration...")
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
    print(f"🔍 Subdomain Enumeration - {target}")
    print("=" * 50)
    
    start_time = datetime.now()
    
    try:
        if not target:
            print("❌ FAILED: Empty target provided")
            return {"status": "FAILED", "error": "Empty target"}
        
        domain = clean_domain_input(target)
        
        if not validate_domain(domain):
            print("❌ FAILED: Invalid domain format")
            return {"status": "FAILED", "error": "Invalid domain format"}
        
        print(f"🎯 Target: {domain}")
        print()
        
        # Perform subdomain enumeration
        results = perform_subdomain_enumeration(target)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        summary = results["summary"]
        total_found = summary["active_subdomains"]
        
        if total_found > 0:
            print(f"✅ SUCCESS: Found {total_found} active subdomains")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Display brute force results
            brute_force = results["brute_force"]
            if brute_force:
                print(f"🚀 Brute Force Results ({len(brute_force)}):")
                for subdomain in brute_force[:10]:  # Show first 10
                    status_info = ""
                    if subdomain.get("http_status"):
                        status_info = f" [{subdomain['http_status']}]"
                    if subdomain.get("title"):
                        status_info += f" - {subdomain['title'][:50]}"
                    
                    print(f"   • {subdomain['subdomain']}{status_info}")
                    if len(subdomain.get("ip_addresses", [])) > 0:
                        print(f"     └─ IP: {', '.join(subdomain['ip_addresses'][:3])}")
                
                if len(brute_force) > 10:
                    print(f"   ... and {len(brute_force) - 10} more")
                print()
            
            # Display certificate transparency results
            ct_results = results["certificate_transparency"]
            if ct_results:
                print(f"📜 Certificate Transparency ({len(ct_results)}):")
                for subdomain in ct_results[:10]:
                    print(f"   • {subdomain}")
                if len(ct_results) > 10:
                    print(f"   ... and {len(ct_results) - 10} more")
                print()
            
            # Display summary statistics
            print("📊 Summary:")
            print(f"   • Total unique subdomains: {summary['total_unique_subdomains']}")
            print(f"   • Active subdomains: {summary['active_subdomains']}")
            print(f"   • Brute force discovered: {summary['brute_force_found']}")
            print(f"   • Certificate transparency: {summary['certificate_transparency_found']}")
            
            return {
                "status": "SUCCESS",
                "data": results,
                "count": total_found,
                "execution_time": execution_time,
                "severity": "HIGH" if total_found > 20 else "MEDIUM" if total_found > 5 else "LOW"
            }
        else:
            print("ℹ️  NO DATA: No subdomains found")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            return {"status": "NO_DATA", "execution_time": execution_time}
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Enumeration stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("⏰ TIMEOUT: Request timeout during enumeration")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("🌐 ERROR: Connection error during DNS lookups")
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
        print("Usage: python subdomain_enum.py <domain>")
        print("Example: python subdomain_enum.py example.com")
        sys.exit(1)