#!/usr/bin/env python3
"""
Simple Argus Web Server - Updated with All Modules
Uses only Python standard library
"""

import http.server
import socketserver
import json
import urllib.parse
import uuid
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path
import threading
import time

# Module-specific timeout configuration (in seconds)
MODULE_TIMEOUTS = {
    'data_leak.py': 300,              # 5 minutes - API rate limited
    'subdomain_enum.py': 180,         # 3 minutes - DNS enumeration
    'subdomain_takeover.py': 240,     # 4 minutes - comprehensive testing
    'virustotal_scan.py': 120,        # 2 minutes - API dependent
    'default': 60                     # 1 minute for all other modules
}

def get_module_timeout(module_script):
    """Get timeout for specific module, fallback to default"""
    return MODULE_TIMEOUTS.get(module_script, MODULE_TIMEOUTS['default'])


# Configuration
PORT = 8000
HOST = "localhost"

# Add the Argus root directory to Python path
current_dir = Path.cwd()
argus_root = current_dir.parent.parent  # Go up from web/backend to argus root
sys.path.insert(0, str(argus_root))

print(f"📁 Current directory: {current_dir}")
print(f"📁 Argus root directory: {argus_root}")

# Simple in-memory storage
active_scans = {}
scan_history = {}

# Available modules - ALL 54 modules organized by category
AVAILABLE_MODULES = [
    # Network & Infrastructure (1-19)
    {
        "id": 1,
        "name": "Associated Hosts",
        "script": "associated_hosts.py",
        "category": "Network & Infrastructure",
        "description": "Discover domains associated with the target",
        "requires_api_key": False,
        "estimated_time": 10
    },
    {
        "id": 2,
        "name": "DNS Over HTTPS",
        "script": "dns_over_https.py",
        "category": "Network & Infrastructure",
        "description": "Resolve DNS securely via encrypted channels",
        "requires_api_key": False,
        "estimated_time": 5
    },
    {
        "id": 3,
        "name": "DNS Records",
        "script": "dns_records.py",
        "category": "Network & Infrastructure",
        "description": "Collect DNS records (A, AAAA, MX, etc.)",
        "requires_api_key": False,
        "estimated_time": 5
    },
    {
        "id": 4,
        "name": "DNSSEC Check",
        "script": "dnssec.py",
        "category": "Network & Infrastructure",
        "description": "Verify if DNSSEC is properly configured",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 5,
        "name": "Domain Info",
        "script": "domain_info.py",
        "category": "Network & Infrastructure",
        "description": "Get domain registration details",
        "requires_api_key": False,
        "estimated_time": 15
    },
    {
        "id": 6,
        "name": "Domain Reputation Check",
        "script": "domain_reputation_check.py",
        "category": "Network & Infrastructure",
        "description": "Check domain trustworthiness using reputation sources",
        "requires_api_key": True,
        "estimated_time": 12
    },
    {
        "id": 7,
        "name": "HTTP/2 and HTTP/3 Support Checker",
        "script": "http2_http3_checker.py",
        "category": "Network & Infrastructure",
        "description": "Check if server supports HTTP/2 and HTTP/3",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 8,
        "name": "IP Info",
        "script": "ip_info.py",
        "category": "Network & Infrastructure",
        "description": "Get IP geolocation and ownership details",
        "requires_api_key": False,
        "estimated_time": 5
    },
    {
        "id": 9,
        "name": "Open Ports Scan",
        "script": "open_ports.py",
        "category": "Network & Infrastructure",
        "description": "Scan target for open ports and services",
        "requires_api_key": False,
        "estimated_time": 30
    },
    {
        "id": 10,
        "name": "Server Info",
        "script": "server_info.py",
        "category": "Network & Infrastructure",
        "description": "Extract key server details",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 11,
        "name": "Server Location",
        "script": "server_location.py",
        "category": "Network & Infrastructure",
        "description": "Identify physical location of the server",
        "requires_api_key": False,
        "estimated_time": 5
    },
    {
        "id": 12,
        "name": "SSL Chain Analysis",
        "script": "ssl_chain.py",
        "category": "Network & Infrastructure",
        "description": "Analyze SSL certificate chain",
        "requires_api_key": False,
        "estimated_time": 10
    },
    {
        "id": 13,
        "name": "SSL Expiry Alert",
        "script": "ssl_expiry.py",
        "category": "Network & Infrastructure",
        "description": "Check SSL certificates for upcoming expiry",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 14,
        "name": "TLS Cipher Suites",
        "script": "tls_cipher_suites.py",
        "category": "Network & Infrastructure",
        "description": "List supported TLS ciphers on the server",
        "requires_api_key": False,
        "estimated_time": 15
    },
    {
        "id": 15,
        "name": "TLS Handshake Simulation",
        "script": "tls_handshake.py",
        "category": "Network & Infrastructure",
        "description": "Simulate TLS handshake to check for issues",
        "requires_api_key": False,
        "estimated_time": 12
    },
    {
        "id": 16,
        "name": "Traceroute",
        "script": "traceroute.py",
        "category": "Network & Infrastructure",
        "description": "Trace the path packets take to reach target",
        "requires_api_key": False,
        "estimated_time": 20
    },
    {
        "id": 17,
        "name": "TXT Records",
        "script": "txt_records.py",
        "category": "Network & Infrastructure",
        "description": "Retrieve TXT DNS records",
        "requires_api_key": False,
        "estimated_time": 5
    },
    {
        "id": 18,
        "name": "WHOIS Lookup",
        "script": "whois_lookup.py",
        "category": "Network & Infrastructure",
        "description": "Perform WHOIS queries for domain ownership",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 19,
        "name": "Zone Transfer",
        "script": "zonetransfer.py",
        "category": "Network & Infrastructure",
        "description": "Attempt to perform DNS zone transfers",
        "requires_api_key": False,
        "estimated_time": 10
    },

    # Web Application Analysis (20-36)
    {
        "id": 20,
        "name": "Archive History",
        "script": "archive_history.py",
        "category": "Web Application Analysis",
        "description": "View target's history using internet archives",
        "requires_api_key": False,
        "estimated_time": 10
    },
    {
        "id": 21,
        "name": "Broken Links Detection",
        "script": "broken_links.py",
        "category": "Web Application Analysis",
        "description": "Find broken links that may affect user experience",
        "requires_api_key": False,
        "estimated_time": 25
    },
    {
        "id": 22,
        "name": "Carbon Footprint",
        "script": "carbon_footprint.py",
        "category": "Web Application Analysis",
        "description": "Evaluate environmental impact of website",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 23,
        "name": "CMS Detection",
        "script": "cms_detection.py",
        "category": "Web Application Analysis",
        "description": "Detect CMS type (WordPress, Joomla, etc.)",
        "requires_api_key": False,
        "estimated_time": 10
    },
    {
        "id": 24,
        "name": "Cookies Analyzer",
        "script": "cookies.py",
        "category": "Web Application Analysis",
        "description": "Analyze cookies for security attributes",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 25,
        "name": "Content Discovery",
        "script": "content_discovery.py",
        "category": "Web Application Analysis",
        "description": "Discover hidden directories and files",
        "requires_api_key": False,
        "estimated_time": 30
    },
    {
        "id": 26,
        "name": "Crawler",
        "script": "crawler.py",
        "category": "Web Application Analysis",
        "description": "Crawl site to map structure and discover content",
        "requires_api_key": False,
        "estimated_time": 45
    },
    {
        "id": 27,
        "name": "Robots.txt Analyzer",
        "script": "crawl_rules.py",
        "category": "Web Application Analysis",
        "description": "Analyze robots.txt for hidden resources",
        "requires_api_key": False,
        "estimated_time": 5
    },
    {
        "id": 28,
        "name": "Directory Finder",
        "script": "directory_finder.py",
        "category": "Web Application Analysis",
        "description": "Look for directories not publicly indexed",
        "requires_api_key": False,
        "estimated_time": 60
    },
    {
        "id": 29,
        "name": "Email Harvesting",
        "script": "email_harvester.py",
        "category": "Web Application Analysis",
        "description": "Extract email addresses from target domain",
        "requires_api_key": False,
        "estimated_time": 20
    },
    {
        "id": 30,
        "name": "Performance Monitoring",
        "script": "performance_monitoring.py",
        "category": "Web Application Analysis",
        "description": "Monitor website response time and performance",
        "requires_api_key": True,
        "estimated_time": 15
    },
    {
        "id": 31,
        "name": "Quality Metrics",
        "script": "quality_metrics.py",
        "category": "Web Application Analysis",
        "description": "Assess website quality and user experience",
        "requires_api_key": False,
        "estimated_time": 12
    },
    {
        "id": 32,
        "name": "Redirect Chain",
        "script": "redirect_chain.py",
        "category": "Web Application Analysis",
        "description": "Follow redirects to analyze safety",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 33,
        "name": "Sitemap Parsing",
        "script": "sitemap.py",
        "category": "Web Application Analysis",
        "description": "Extract URLs from website sitemap",
        "requires_api_key": False,
        "estimated_time": 15
    },
    {
        "id": 34,
        "name": "Social Media Presence Scan",
        "script": "social_media.py",
        "category": "Web Application Analysis",
        "description": "Analyze social media profiles linked to target",
        "requires_api_key": False,
        "estimated_time": 20
    },
    {
        "id": 35,
        "name": "Technology Stack Detection",
        "script": "technology_stack.py",
        "category": "Web Application Analysis",
        "description": "Identify technologies and frameworks used",
        "requires_api_key": False,
        "estimated_time": 15
    },
    {
        "id": 36,
        "name": "Third-Party Integrations",
        "script": "third_party_integrations.py",
        "category": "Web Application Analysis",
        "description": "Discover third-party services integrated",
        "requires_api_key": False,
        "estimated_time": 12
    },

    # Security & Threat Intelligence (37-54)
    {
        "id": 37,
        "name": "Censys Reconnaissance",
        "script": "censys.py",
        "category": "Security & Threat Intelligence",
        "description": "Use Censys for in-depth asset details",
        "requires_api_key": True,
        "estimated_time": 15
    },
    {
        "id": 38,
        "name": "Certificate Authority Recon",
        "script": "certificate_authority_recon.py",
        "category": "Security & Threat Intelligence",
        "description": "Examine certificate authority details",
        "requires_api_key": False,
        "estimated_time": 10
    },
    {
        "id": 39,
        "name": "Data Leak Detection",
        "script": "data_leak.py",
        "category": "Security & Threat Intelligence",
        "description": "Check for potential data leaks and exposure",
        "requires_api_key": False,
        "estimated_time": 25
    },
    {
        "id": 40,
        "name": "Exposed Environment Files Checker",
        "script": "exposed_env_files.py",
        "category": "Security & Threat Intelligence",
        "description": "Identify publicly exposed .env files",
        "requires_api_key": False,
        "estimated_time": 12
    },
    {
        "id": 41,
        "name": "Firewall Detection",
        "script": "firewall_detection.py",
        "category": "Security & Threat Intelligence",
        "description": "Identify firewall/WAF protecting the target",
        "requires_api_key": False,
        "estimated_time": 10
    },
    {
        "id": 42,
        "name": "Global Ranking",
        "script": "global_ranking.py",
        "category": "Security & Threat Intelligence",
        "description": "Look up site's global ranking and popularity",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 43,
        "name": "HTTP Headers",
        "script": "http_headers.py",
        "category": "Security & Threat Intelligence",
        "description": "Extract and evaluate HTTP response headers",
        "requires_api_key": False,
        "estimated_time": 10
    },
    {
        "id": 44,
        "name": "HTTP Security Features",
        "script": "http_security.py",
        "category": "Security & Threat Intelligence",
        "description": "Check for secure HTTP headers (HSTS, CSP)",
        "requires_api_key": False,
        "estimated_time": 10
    },
    {
        "id": 45,
        "name": "Malware & Phishing Check",
        "script": "malware_phishing.py",
        "category": "Security & Threat Intelligence",
        "description": "Scan site for malware and phishing risks",
        "requires_api_key": True,
        "estimated_time": 15
    },
    {
        "id": 46,
        "name": "Pastebin Monitoring",
        "script": "pastebin_monitoring.py",
        "category": "Security & Threat Intelligence",
        "description": "Search paste sites for target-related leaks",
        "requires_api_key": False,
        "estimated_time": 30
    },
    {
        "id": 47,
        "name": "Privacy & GDPR Compliance",
        "script": "privacy_gdpr.py",
        "category": "Security & Threat Intelligence",
        "description": "Verify GDPR and privacy regulation compliance",
        "requires_api_key": False,
        "estimated_time": 15
    },
    {
        "id": 48,
        "name": "Security.txt Check",
        "script": "security_txt.py",
        "category": "Security & Threat Intelligence",
        "description": "Locate and analyze security.txt file",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 49,
        "name": "Shodan Reconnaissance",
        "script": "shodan.py",
        "category": "Security & Threat Intelligence",
        "description": "Use Shodan to discover ports and vulnerabilities",
        "requires_api_key": True,
        "estimated_time": 15
    },
    {
        "id": 50,
        "name": "SSL Labs Report",
        "script": "ssl_labs_report.py",
        "category": "Security & Threat Intelligence",
        "description": "Get detailed SSL/TLS assessment via SSL Labs",
        "requires_api_key": False,
        "estimated_time": 30
    },
    {
        "id": 51,
        "name": "SSL Pinning Check",
        "script": "ssl_pinning_check.py",
        "category": "Security & Threat Intelligence",
        "description": "Check if SSL pinning is implemented",
        "requires_api_key": False,
        "estimated_time": 8
    },
    {
        "id": 52,
        "name": "Subdomain Enumeration",
        "script": "subdomain_enum.py",
        "category": "Security & Threat Intelligence",
        "description": "Discover subdomains of target domain",
        "requires_api_key": False,
        "estimated_time": 20
    },
    {
        "id": 53,
        "name": "Subdomain Takeover",
        "script": "subdomain_takeover.py",
        "category": "Security & Threat Intelligence",
        "description": "Test if subdomains are vulnerable to takeover",
        "requires_api_key": False,
        "estimated_time": 25
    },
    {
        "id": 54,
        "name": "VirusTotal Scan",
        "script": "virustotal_scan.py",
        "category": "Security & Threat Intelligence",
        "description": "Check target reputation using VirusTotal",
        "requires_api_key": True,
        "estimated_time": 12
    }
]

class ArgusHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests"""
        try:
            if self.path == '/':
                self.send_json_response({
                    "message": "Argus Web Interface API",
                    "version": "1.0.0",
                    "modules_available": len(AVAILABLE_MODULES),
                    "status": "running"
                })
            
            elif self.path == '/api/health':
                self.handle_health()
            
            elif self.path == '/api/modules':
                self.handle_get_modules()
            
            elif self.path == '/api/scans':
                self.handle_list_scans()
            
            elif self.path.startswith('/api/scans/'):
                scan_id = self.path.split('/')[-1]
                self.handle_get_scan(scan_id)
            
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            self.send_error(500, f"Internal Server Error: {str(e)}")

    def do_POST(self):
        """Handle POST requests"""
        try:
            if self.path == '/api/scans':
                self.handle_create_scan()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            self.send_error(500, f"Internal Server Error: {str(e)}")

    def send_json_response(self, data, status_code=200):
        """Send JSON response with CORS headers"""
        response_json = json.dumps(data, indent=2)
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', str(len(response_json)))
        self.end_headers()
        self.wfile.write(response_json.encode())

    def handle_health(self):
        """Health check endpoint"""
        modules_dir = argus_root / "modules"
        modules_exist = modules_dir.exists()
        
        if modules_exist:
            module_files = list(modules_dir.glob("*.py"))
            module_count = len(module_files)
        else:
            module_count = 0
        
        health_data = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "active_scans": len(active_scans),
            "completed_scans": len(scan_history),
            "modules_directory_found": modules_exist,
            "module_files_found": module_count,
            "total_available_modules": len(AVAILABLE_MODULES),
            "argus_root": str(argus_root)
        }
        
        self.send_json_response(health_data)

    def handle_get_modules(self):
        """Get available modules"""
        categories = {}
        for module in AVAILABLE_MODULES:
            category = module["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(module["script"])
        
        response_data = {
            "modules": AVAILABLE_MODULES,
            "categories": categories,
            "total_count": len(AVAILABLE_MODULES)
        }
        
        self.send_json_response(response_data)

    def handle_create_scan(self):
        """Create a new scan"""
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            scan_data = json.loads(post_data.decode())
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return
        
        # Validate input
        target = scan_data.get("target", "").strip()
        modules = scan_data.get("modules", [])
        
        if not target:
            self.send_json_response({"error": "Target is required"}, 400)
            return
        
        if not modules:
            self.send_json_response({"error": "At least one module must be selected"}, 400)
            return
        
        # Validate modules exist
        valid_modules = [m["script"] for m in AVAILABLE_MODULES]
        invalid_modules = [m for m in modules if m not in valid_modules]
        if invalid_modules:
            self.send_json_response({
                "error": f"Invalid modules: {', '.join(invalid_modules)}"
            }, 400)
            return
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan record
        scan_record = {
            "scan_id": scan_id,
            "target": target,
            "modules": modules,
            "status": "queued",
            "created_at": datetime.utcnow().isoformat(),
            "progress": 0,
            "total_modules": len(modules),
            "completed_modules": 0,
            "module_results": []
        }
        
        active_scans[scan_id] = scan_record
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=execute_scan, args=(scan_id,))
        scan_thread.daemon = True
        scan_thread.start()
        
        print(f"✅ Created scan {scan_id} for target {target} with {len(modules)} modules")
        
        response_data = {
            "scan_id": scan_id,
            "status": "queued",
            "message": "Scan created successfully",
            "target": target,
            "modules": modules
        }
        
        self.send_json_response(response_data, 201)

    def handle_get_scan(self, scan_id):
        """Get scan status"""
        if scan_id in active_scans:
            self.send_json_response(active_scans[scan_id])
        elif scan_id in scan_history:
            self.send_json_response(scan_history[scan_id])
        else:
            self.send_json_response({"error": "Scan not found"}, 404)

    def handle_list_scans(self):
        """List all scans"""
        all_scans = list(scan_history.values()) + list(active_scans.values())
        all_scans.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        response_data = {
            "scans": all_scans[:50],  # Limit to 50 most recent
            "total": len(all_scans)
        }
        
        self.send_json_response(response_data)

def execute_scan(scan_id):
    """Execute a scan by running the actual Argus modules"""
    if scan_id not in active_scans:
        print(f"❌ Scan {scan_id} not found in active scans")
        return
    
    scan = active_scans[scan_id]
    modules = scan["modules"]
    target = scan["target"]
    
    print(f"🚀 Starting scan {scan_id} for target {target}")
    
    try:
        scan["status"] = "running"
        scan["started_at"] = datetime.utcnow().isoformat()
        
        # Get the modules directory
        modules_dir = argus_root / "modules"
        
        if not modules_dir.exists():
            raise Exception(f"Modules directory not found: {modules_dir}")
        
        # Execute each module
        for i, module_script in enumerate(modules):
            module_path = modules_dir / module_script
            
            print(f"📦 Executing module {i+1}/{len(modules)}: {module_script}")
            
            if not module_path.exists():
                print(f"❌ Module file not found: {module_path}")
                result = {
                    "module_name": module_script,
                    "status": "failed",
                    "error": f"Module file not found: {module_path}",
                    "execution_time": 0
                }
            else:
                # Execute the module
                start_time = datetime.utcnow()
                
                try:
                    print(f"   Running: python {module_path} {target}")
                    
                    # Run the module as a subprocess
                    process = subprocess.run(
                        [sys.executable, str(module_path), target],
                        capture_output=True,
                        text=True,
                        timeout=get_module_timeout(module_script),  # Dynamic timeout per module
                        cwd=str(argus_root)
                    )
                    
                    end_time = datetime.utcnow()
                    execution_time = (end_time - start_time).total_seconds()
                    
                    result = {
                        "module_name": module_script,
                        "status": "success" if process.returncode == 0 else "failed",
                        "output": process.stdout,
                        "error": process.stderr if process.stderr else None,
                        "execution_time": execution_time,
                        "return_code": process.returncode
                    }
                    
                    if process.returncode == 0:
                        print(f"   ✅ Success: {module_script}")
                    else:
                        print(f"   ❌ Failed: {module_script} (exit code: {process.returncode})")
                        if process.stderr:
                            print(f"      Error: {process.stderr[:200]}...")
                    
                except subprocess.TimeoutExpired:
                    print(f"   ⏰ Timeout: {module_script}")
                    result = {
                        "module_name": module_script,
                        "status": "failed",
                        "error": f"Module execution timed out after {get_module_timeout(module_script)} seconds",
                        "execution_time": 60
                    }
                except Exception as e:
                    print(f"   ❌ Exception: {module_script} - {e}")
                    result = {
                        "module_name": module_script,
                        "status": "failed", 
                        "error": f"Execution error: {str(e)}",
                        "execution_time": 0
                    }
            
            # Update scan progress
            scan["module_results"].append(result)
            scan["completed_modules"] = i + 1
            scan["progress"] = ((i + 1) / len(modules)) * 100
            scan["current_module"] = module_script
        
        # Complete scan
        scan["status"] = "completed"
        scan["completed_at"] = datetime.utcnow().isoformat()
        scan["progress"] = 100
        scan["current_module"] = None
        
        # Generate summary
        successful = sum(1 for r in scan["module_results"] if r["status"] == "success")
        scan["summary"] = {
            "total_modules": len(modules),
            "successful_modules": successful,
            "failed_modules": len(modules) - successful,
            "success_rate": (successful / len(modules) * 100) if modules else 0
        }
        
        # Move to history
        scan_history[scan_id] = scan.copy()
        del active_scans[scan_id]
        
        print(f"🎉 Scan {scan_id} completed successfully - {successful}/{len(modules)} modules succeeded")
        
    except Exception as e:
        print(f"❌ Scan {scan_id} failed: {str(e)}")
        scan["status"] = "failed"
        scan["completed_at"] = datetime.utcnow().isoformat()
        scan["error"] = str(e)
        
        # Move to history
        scan_history[scan_id] = scan.copy()
        del active_scans[scan_id]

def main():
    print("🚀 Starting Argus Web Interface - Simple HTTP Server...")
    print(f"🌐 Server will be available at: http://{HOST}:{PORT}")
    print(f"📚 API endpoints:")
    print(f"   - http://{HOST}:{PORT}/api/health")
    print(f"   - http://{HOST}:{PORT}/api/modules")
    print(f"   - http://{HOST}:{PORT}/api/scans")
    print("=" * 50)
    
    # Check if modules directory exists
    modules_dir = argus_root / "modules"
    if modules_dir.exists():
        module_files = list(modules_dir.glob("*.py"))
        print(f"✅ Found {len(module_files)} module files in {modules_dir}")
        print(f"✅ Configured {len(AVAILABLE_MODULES)} modules in API")
        
        # Check for some key modules
        key_modules = ["dns_records.py", "http_headers.py", "domain_info.py", "ssl_chain.py", "subdomain_enum.py"]
        for module in key_modules:
            if (modules_dir / module).exists():
                print(f"   ✅ {module}")
            else:
                print(f"   ⚠️  {module} (missing)")
    else:
        print(f"❌ Modules directory not found at {modules_dir}")
        print("   Make sure you're running this from the correct Argus project directory")
    
    print("=" * 50)
    
    try:
        with socketserver.TCPServer((HOST, PORT), ArgusHTTPHandler) as httpd:
            print(f"✅ Server started successfully!")
            print(f"🔗 Visit: http://{HOST}:{PORT}/api/health")
            print(f"🎯 Total modules available: {len(AVAILABLE_MODULES)}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()