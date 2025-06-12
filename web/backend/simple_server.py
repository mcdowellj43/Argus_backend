#!/usr/bin/env python3
"""
Simple Argus Web Server - No external dependencies
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

# Available modules
AVAILABLE_MODULES = [
    {
        "id": 3,
        "name": "DNS Records",
        "script": "dns_records.py",
        "category": "Network & Infrastructure",
        "description": "Retrieve DNS records (A, AAAA, MX, etc.)",
        "requires_api_key": False,
        "estimated_time": 5
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
        "id": 8,
        "name": "IP Info",
        "script": "ip_info.py",
        "category": "Network & Infrastructure", 
        "description": "Get IP geolocation and ownership details",
        "requires_api_key": False,
        "estimated_time": 5
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
        "id": 43,
        "name": "HTTP Headers",
        "script": "http_headers.py",
        "category": "Security & Threat Intelligence", 
        "description": "Analyze HTTP security headers",
        "requires_api_key": False,
        "estimated_time": 10
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
            "argus_root": str(argus_root)
        }
        
        self.send_json_response(health_data)

    def handle_get_modules(self):
        """Get available modules"""
        categories = {
            "Network & Infrastructure": [m["script"] for m in AVAILABLE_MODULES if m["category"] == "Network & Infrastructure"],
            "Security & Threat Intelligence": [m["script"] for m in AVAILABLE_MODULES if m["category"] == "Security & Threat Intelligence"]
        }
        
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
        
        print(f"✅ Created scan {scan_id} for target {target} with modules: {modules}")
        
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
                        timeout=60,  # 1 minute timeout per module
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
                        "error": "Module execution timed out after 60 seconds",
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
        
        # Check for some key modules
        key_modules = ["dns_records.py", "http_headers.py", "domain_info.py"]
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
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()