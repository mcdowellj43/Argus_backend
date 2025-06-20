#!/usr/bin/env python3
"""
Improved Subdomain Takeover Module - Clean Output with Success/Failure Indicators
"""

import os
import sys
import dns.resolver
import dns.exception
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain
from config.settings import USER_AGENT, DEFAULT_TIMEOUT

def get_vulnerable_services():
    """Get list of services vulnerable to subdomain takeover"""
    return {
        # Cloud services
        'amazonaws.com': {
            'service': 'AWS S3/CloudFront',
            'signatures': ['NoSuchBucket', 'The specified bucket does not exist'],
            'risk': 'HIGH'
        },
        'azurewebsites.net': {
            'service': 'Azure App Service',
            'signatures': ['404 - Web app not found', 'The resource you are looking for has been removed'],
            'risk': 'HIGH'
        },
        'cloudfront.net': {
            'service': 'AWS CloudFront',
            'signatures': ['Bad request', 'ERROR: The request could not be satisfied'],
            'risk': 'HIGH'
        },
        'herokuapp.com': {
            'service': 'Heroku',
            'signatures': ['No such app', 'There\'s nothing here, yet'],
            'risk': 'HIGH'
        },
        'github.io': {
            'service': 'GitHub Pages',
            'signatures': ['There isn\'t a GitHub Pages site here', '404 - File not found'],
            'risk': 'MEDIUM'
        },
        'netlify.app': {
            'service': 'Netlify',
            'signatures': ['Not Found - Request ID', 'Page not found'],
            'risk': 'HIGH'
        },
        'vercel.app': {
            'service': 'Vercel',
            'signatures': ['The deployment could not be found', '404: NOT_FOUND'],
            'risk': 'HIGH'
        },
        'surge.sh': {
            'service': 'Surge.sh',
            'signatures': ['project not found', 'repository not found'],
            'risk': 'HIGH'
        },
        'wordpress.com': {
            'service': 'WordPress.com',
            'signatures': ['Do you want to register', 'doesn\'t exist'],
            'risk': 'MEDIUM'
        },
        'tumblr.com': {
            'service': 'Tumblr',
            'signatures': ['There\'s nothing here', 'Whatever you were looking for doesn\'t currently exist'],
            'risk': 'MEDIUM'
        },
        'bitbucket.io': {
            'service': 'Bitbucket',
            'signatures': ['Repository not found', 'The page you\'re looking for doesn\'t exist'],
            'risk': 'MEDIUM'
        },
        'zendesk.com': {
            'service': 'Zendesk',
            'signatures': ['Help Center Closed', 'this help center no longer exists'],
            'risk': 'HIGH'
        },
        'freshdesk.com': {
            'service': 'Freshdesk',
            'signatures': ['May be this is still fresh!', 'Page not found'],
            'risk': 'HIGH'
        },
        'shopify.com': {
            'service': 'Shopify',
            'signatures': ['Sorry, this shop is currently unavailable', 'This shop is unavailable'],
            'risk': 'HIGH'
        },
        'myshopify.com': {
            'service': 'Shopify',
            'signatures': ['Sorry, this shop is currently unavailable', 'This shop is unavailable'],
            'risk': 'HIGH'
        }
    }

def check_dns_record(subdomain):
    """Check DNS records for a subdomain"""
    try:
        # Check A records
        a_records = []
        try:
            answers = dns.resolver.resolve(subdomain, 'A', lifetime=5)
            a_records = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        
        # Check CNAME records
        cname_records = []
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=5)
            cname_records = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        
        return {
            "subdomain": subdomain,
            "a_records": a_records,
            "cname_records": cname_records,
            "has_records": bool(a_records or cname_records)
        }
        
    except dns.exception.DNSException:
        return {
            "subdomain": subdomain,
            "a_records": [],
            "cname_records": [],
            "has_records": False,
            "error": "DNS lookup failed"
        }

def check_http_response(subdomain):
    """Check HTTP response for takeover signatures"""
    vulnerable_services = get_vulnerable_services()
    
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{subdomain}"
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            content = response.text.lower()
            
            # Check for vulnerable service signatures
            for service_domain, service_info in vulnerable_services.items():
                if service_domain in subdomain.lower():
                    # Check if any signature matches
                    for signature in service_info['signatures']:
                        if signature.lower() in content:
                            return {
                                "vulnerable": True,
                                "service": service_info['service'],
                                "signature": signature,
                                "risk": service_info['risk'],
                                "status_code": response.status_code,
                                "protocol": protocol,
                                "response_size": len(content)
                            }
            
            # Check for general takeover indicators
            takeover_indicators = [
                'domain not found',
                'no such host',
                'project not found',
                'repository not found',
                'page not found',
                'this domain is for sale',
                'parked domain',
                'suspended domain'
            ]
            
            for indicator in takeover_indicators:
                if indicator in content:
                    return {
                        "potentially_vulnerable": True,
                        "indicator": indicator,
                        "status_code": response.status_code,
                        "protocol": protocol,
                        "response_size": len(content),
                        "needs_manual_verification": True
                    }
            
            return {
                "vulnerable": False,
                "status_code": response.status_code,
                "protocol": protocol,
                "response_size": len(content)
            }
            
        except requests.exceptions.RequestException:
            continue
    
    return {"error": "No HTTP response"}

def analyze_subdomain_takeover(subdomain):
    """Analyze a subdomain for takeover vulnerability"""
    result = {
        "subdomain": subdomain,
        "dns_info": {},
        "http_info": {},
        "vulnerability_assessment": {},
        "timestamp": datetime.now().isoformat()
    }
    
    # Check DNS records
    dns_info = check_dns_record(subdomain)
    result["dns_info"] = dns_info
    
    # Check HTTP response
    http_info = check_http_response(subdomain)
    result["http_info"] = http_info
    
    # Assess vulnerability
    vulnerability = assess_vulnerability(dns_info, http_info)
    result["vulnerability_assessment"] = vulnerability
    
    return result

def assess_vulnerability(dns_info, http_info):
    """Assess overall vulnerability based on DNS and HTTP analysis"""
    assessment = {
        "risk_level": "LOW",
        "vulnerable": False,
        "reasons": [],
        "recommendations": []
    }
    
    # Check for dangling DNS records
    if dns_info.get("cname_records"):
        cname = dns_info["cname_records"][0]
        if not dns_info.get("a_records"):
            assessment["reasons"].append("CNAME record exists but no A record")
            assessment["risk_level"] = "MEDIUM"
    
    # Check HTTP vulnerability indicators
    if http_info.get("vulnerable"):
        assessment["vulnerable"] = True
        assessment["risk_level"] = http_info.get("risk", "HIGH")
        assessment["reasons"].append(f"Vulnerable to {http_info['service']} takeover")
        assessment["recommendations"].append("Remove dangling DNS records immediately")
        assessment["recommendations"].append("Claim the external service or update DNS")
    
    elif http_info.get("potentially_vulnerable"):
        assessment["risk_level"] = "MEDIUM"
        assessment["reasons"].append(f"Potential vulnerability: {http_info['indicator']}")
        assessment["recommendations"].append("Manual verification required")
    
    # Check for missing DNS records
    if not dns_info.get("has_records") and not dns_info.get("error"):
        assessment["reasons"].append("No DNS records found")
        assessment["recommendations"].append("Remove subdomain or configure proper records")
    
    return assessment

def get_subdomains_to_test(domain):
    """Get list of subdomains to test (this would typically come from enumeration)"""
    # Common subdomains that might be vulnerable
    common_subdomains = [
        'www', 'api', 'app', 'blog', 'dev', 'test', 'staging',
        'admin', 'portal', 'dashboard', 'support', 'help',
        'docs', 'wiki', 'cdn', 'static', 'assets', 'files'
    ]
    
    return [f"{sub}.{domain}" for sub in common_subdomains]

def perform_takeover_scan(target, custom_subdomains=None):
    """Perform subdomain takeover scan"""
    domain = clean_domain_input(target)
    
    # Get subdomains to test
    if custom_subdomains:
        subdomains = custom_subdomains
    else:
        subdomains = get_subdomains_to_test(domain)
    
    results = {
        "domain": domain,
        "subdomains_tested": len(subdomains),
        "vulnerable_subdomains": [],
        "potentially_vulnerable": [],
        "secure_subdomains": [],
        "errors": []
    }
    
    print(f"🔍 Testing {len(subdomains)} subdomains for takeover vulnerabilities...")
    
    # Test subdomains concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {
            executor.submit(analyze_subdomain_takeover, subdomain): subdomain 
            for subdomain in subdomains
        }
        
        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                result = future.result()
                
                vulnerability = result["vulnerability_assessment"]
                
                if vulnerability.get("vulnerable"):
                    results["vulnerable_subdomains"].append(result)
                elif vulnerability.get("risk_level") == "MEDIUM":
                    results["potentially_vulnerable"].append(result)
                elif result["dns_info"].get("has_records") or result["http_info"].get("status_code"):
                    results["secure_subdomains"].append(result)
                else:
                    # No records found - could be cleaned up
                    pass
                    
            except Exception as e:
                results["errors"].append({
                    "subdomain": subdomain,
                    "error": str(e)
                })
    
    return results

def main(target, subdomain_list=None):
    """Main execution with clean output"""
    print(f"🔍 Subdomain Takeover Check - {target}")
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
        
        # Load custom subdomain list if provided
        custom_subdomains = None
        if subdomain_list and os.path.exists(subdomain_list):
            try:
                with open(subdomain_list, 'r') as f:
                    custom_subdomains = [line.strip() for line in f if line.strip()]
                print(f"📝 Loaded {len(custom_subdomains)} subdomains from file")
            except Exception as e:
                print(f"⚠️  Warning: Could not load subdomain list: {e}")
        
        print()
        
        # Perform takeover scan
        results = perform_takeover_scan(target, custom_subdomains)
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Analyze results
        vulnerable_count = len(results["vulnerable_subdomains"])
        potentially_vulnerable_count = len(results["potentially_vulnerable"])
        total_issues = vulnerable_count + potentially_vulnerable_count
        
        if vulnerable_count > 0:
            print(f"🚨 CRITICAL: Found {vulnerable_count} vulnerable subdomains!")
            print(f"⚠️  Additional: {potentially_vulnerable_count} potentially vulnerable")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            # Display vulnerable subdomains
            print("🚨 Confirmed Vulnerabilities:")
            for vuln in results["vulnerable_subdomains"]:
                subdomain = vuln["subdomain"]
                assessment = vuln["vulnerability_assessment"]
                http_info = vuln["http_info"]
                
                print(f"   • {subdomain}")
                print(f"     └─ Risk: {assessment['risk_level']}")
                print(f"     └─ Service: {http_info.get('service', 'Unknown')}")
                print(f"     └─ Reason: {', '.join(assessment['reasons'])}")
            print()
            
            # Display potentially vulnerable
            if results["potentially_vulnerable"]:
                print("⚠️  Requires Manual Verification:")
                for vuln in results["potentially_vulnerable"]:
                    subdomain = vuln["subdomain"]
                    assessment = vuln["vulnerability_assessment"]
                    print(f"   • {subdomain}")
                    print(f"     └─ Reason: {', '.join(assessment['reasons'])}")
                print()
            
            return {
                "status": "VULNERABLE",
                "data": results,
                "count": total_issues,
                "execution_time": execution_time,
                "severity": "CRITICAL" if vulnerable_count > 0 else "HIGH"
            }
        
        elif potentially_vulnerable_count > 0:
            print(f"⚠️  POTENTIAL ISSUES: Found {potentially_vulnerable_count} subdomains requiring verification")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            print()
            
            print("⚠️  Manual Verification Required:")
            for vuln in results["potentially_vulnerable"]:
                subdomain = vuln["subdomain"]
                assessment = vuln["vulnerability_assessment"]
                print(f"   • {subdomain}")
                print(f"     └─ Reason: {', '.join(assessment['reasons'])}")
            print()
            
            return {
                "status": "POTENTIAL_ISSUES",
                "data": results,
                "count": potentially_vulnerable_count,
                "execution_time": execution_time,
                "severity": "MEDIUM"
            }
        
        else:
            secure_count = len(results["secure_subdomains"])
            print(f"✅ SECURE: No subdomain takeover vulnerabilities found")
            print(f"🔒 Tested: {results['subdomains_tested']} subdomains")
            print(f"✓ Secure: {secure_count} subdomains responding normally")
            print(f"⏱️  Execution time: {execution_time:.2f}s")
            
            return {
                "status": "SECURE",
                "data": results,
                "count": 0,
                "execution_time": execution_time
            }
            
    except KeyboardInterrupt:
        print("⚠️  INTERRUPTED: Scan stopped by user")
        return {"status": "INTERRUPTED"}
        
    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        error_msg = str(e)
        
        if "timeout" in error_msg.lower():
            print("⏰ TIMEOUT: Request timeout during takeover scan")
            status = "TIMEOUT"
        elif "connection" in error_msg.lower():
            print("🌐 ERROR: Connection error during DNS/HTTP checks")
            status = "CONNECTION_ERROR"
        else:
            print(f"❌ ERROR: {error_msg}")
            status = "ERROR"
        
        print(f"⏱️  Execution time: {execution_time:.2f}s")
        return {"status": status, "error": error_msg, "execution_time": execution_time}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        subdomain_list = sys.argv[2] if len(sys.argv) > 2 else None
        main(target, subdomain_list)
    else:
        print("❌ ERROR: No target provided")
        print("Usage: python subdomain_takeover.py <domain> [subdomain_list.txt]")
        print("Example: python subdomain_takeover.py example.com")
        print("Example: python subdomain_takeover.py example.com subdomains.txt")
        sys.exit(1)