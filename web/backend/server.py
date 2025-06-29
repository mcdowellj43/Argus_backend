import json
import time
import uuid
from datetime import datetime
from pathlib import Path
import sys

# Add the current directory to Python path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Import from local modules
from argus_config import PORT, HOST, ENHANCED_MODULES
from argus_core import (
    execute_module_with_clean_output, aggregate_scan_findings,
    format_enhanced_scan_response, format_findings_for_frontend,
    calculate_scan_progress, calculate_risk_score, determine_risk_level
)

# In-memory storage for scans
active_scans = {}
scan_history = {}

# =============================================================================
# ENHANCED SCAN EXECUTION WITH PROGRESS TRACKING
# =============================================================================

def execute_scan_with_progress(target, modules=None, scan_id=None):
    """Execute a scan with real-time progress tracking"""
    if not scan_id:
        scan_id = str(uuid.uuid4())
    
    if not modules:
        modules = ENHANCED_MODULES
    
    # Initialize scan data
    scan_data = {
        "scan_id": scan_id,
        "target": target,
        "modules": modules,
        "status": "running",
        "created_at": datetime.now().isoformat(),
        "completed_at": None,
        "total_execution_time": 0,
        "module_results": [],
        "progress": 0,
        "current_module": None
    }
    
    # Store in active scans
    active_scans[scan_id] = scan_data
    
    print(f"🚀 Starting scan {scan_id} for target: {target}")
    print(f"📋 Modules to execute: {len(modules)}")
    
    start_time = time.time()
    
    try:
        for i, module_script in enumerate(modules):
            # Update current module
            scan_data["current_module"] = module_script
            scan_data["progress"] = round((i / len(modules)) * 100, 1)
            
            print(f"🔍 [{i+1}/{len(modules)}] Executing {module_script}")
            
            # Execute module
            module_result = execute_module_with_clean_output(module_script, target, scan_id)
            scan_data["module_results"].append(module_result)
            
            # Update progress
            scan_data["progress"] = round(((i + 1) / len(modules)) * 100, 1)
            
            print(f"✅ {module_script}: {module_result['status']} ({module_result['count']} findings)")
        
        # Calculate final statistics
        total_time = time.time() - start_time
        scan_data.update({
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "total_execution_time": round(total_time, 2),
            "progress": 100,
            "current_module": None
        })
        
        # Calculate risk assessment
        risk_score = calculate_risk_score(scan_data)
        risk_level = determine_risk_level(risk_score)
        
        scan_data.update({
            "risk_score": risk_score,
            "risk_level": risk_level
        })
        
        print(f"🎉 Scan {scan_id} completed in {total_time:.2f}s")
        print(f"📊 Risk Score: {risk_score} ({risk_level})")
        
        # Move to history
        scan_history[scan_id] = scan_data
        if scan_id in active_scans:
            del active_scans[scan_id]
        
        return scan_data
        
    except Exception as e:
        scan_data.update({
            "status": "error",
            "error": str(e),
            "completed_at": datetime.now().isoformat(),
            "total_execution_time": time.time() - start_time
        })
        
        print(f"❌ Scan {scan_id} failed: {e}")
        
        # Move to history even if failed
        scan_history[scan_id] = scan_data
        if scan_id in active_scans:
            del active_scans[scan_id]
        
        return scan_data

# =============================================================================
# ENHANCED API ENDPOINTS
# =============================================================================

def get_scan_status(scan_id):
    """Get current status of a scan with enhanced progress information"""
    # Check active scans first
    if scan_id in active_scans:
        scan_data = active_scans[scan_id].copy()
        return calculate_scan_progress(scan_data)
    
    # Check completed scans
    if scan_id in scan_history:
        scan_data = scan_history[scan_id].copy()
        return calculate_scan_progress(scan_data)
    
    return {"error": "Scan not found"}

def get_scan_results(scan_id):
    """Get complete scan results with enhanced findings"""
    if scan_id in scan_history:
        scan_data = scan_history[scan_id].copy()
        return format_enhanced_scan_response(scan_data)
    
    if scan_id in active_scans:
        scan_data = active_scans[scan_id].copy()
        return format_enhanced_scan_response(scan_data)
    
    return {"error": "Scan not found"}

def get_findings_data(scan_id):
    """Get findings data formatted for frontend consumption"""
    if scan_id in scan_history:
        scan_data = scan_history[scan_id].copy()
        return format_findings_for_frontend(scan_data)
    
    if scan_id in active_scans:
        scan_data = active_scans[scan_id].copy()
        return format_findings_for_frontend(scan_data)
    
    return {"error": "Scan not found"}

def get_available_modules():
    """Get list of available modules with metadata"""
    from argus_config import ENHANCED_MODULE_NAMES, ENHANCED_MODULE_CATEGORIES
    
    modules = []
    for module_script in ENHANCED_MODULES:
        module_info = {
            "script": module_script,
            "name": ENHANCED_MODULE_NAMES.get(module_script, module_script),
            "category": ENHANCED_MODULE_CATEGORIES.get(module_script, "General"),
            "enhanced": True
        }
        modules.append(module_info)
    
    return modules

def get_scan_history():
    """Get list of all completed scans"""
    history = []
    for scan_id, scan_data in scan_history.items():
        history_item = {
            "scan_id": scan_id,
            "target": scan_data.get("target"),
            "status": scan_data.get("status"),
            "created_at": scan_data.get("created_at"),
            "completed_at": scan_data.get("completed_at"),
            "total_execution_time": scan_data.get("total_execution_time", 0),
            "risk_score": scan_data.get("risk_score", 0),
            "risk_level": scan_data.get("risk_level", "UNKNOWN"),
            "total_findings": len(scan_data.get("module_results", []))
        }
        history.append(history_item)
    
    # Sort by creation date (newest first)
    history.sort(key=lambda x: x["created_at"], reverse=True)
    return history

def get_active_scans():
    """Get list of currently running scans"""
    active = []
    for scan_id, scan_data in active_scans.items():
        active_item = {
            "scan_id": scan_id,
            "target": scan_data.get("target"),
            "status": scan_data.get("status"),
            "created_at": scan_data.get("created_at"),
            "progress": scan_data.get("progress", 0),
            "current_module": scan_data.get("current_module"),
            "total_modules": len(scan_data.get("modules", [])),
            "completed_modules": len(scan_data.get("module_results", []))
        }
        active.append(active_item)
    
    return active

# =============================================================================
# HTTP SERVER IMPLEMENTATION
# =============================================================================

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class ArgusRequestHandler(BaseHTTPRequestHandler):
    """Enhanced HTTP request handler for ARGUS API"""
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            # Parse URL and query parameters
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Set CORS headers
            self.send_cors_headers()
            
            # Route requests
            if path == "/api/health":
                self.handle_health_check()
            elif path == "/api/modules":
                self.handle_get_modules()
            elif path == "/api/scans":
                self.handle_get_scans()
            elif path == "/api/scans/active":
                self.handle_get_active_scans()
            elif path.startswith("/api/scan/"):
                scan_id = path.split("/")[-1]
                if "results" in query_params:
                    self.handle_get_scan_results(scan_id)
                elif "findings" in query_params:
                    self.handle_get_scan_findings(scan_id)
                else:
                    self.handle_get_scan_status(scan_id)
            else:
                self.send_error(404, "Endpoint not found")
                
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def do_POST(self):
        """Handle POST requests"""
        try:
            # Parse URL
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            
            # Set CORS headers
            self.send_cors_headers()
            
            # Route requests
            if path == "/api/scan":
                self.handle_start_scan()
            else:
                self.send_error(404, "Endpoint not found")
                
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_cors_headers()
        self.send_response(200)
        self.end_headers()
    
    def send_cors_headers(self):
        """Send CORS headers for cross-origin requests"""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
    
    def handle_health_check(self):
        """Handle health check endpoint"""
        response = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "active_scans": len(active_scans),
            "total_scans": len(scan_history)
        }
        self.send_json_response(response)
    
    def handle_get_modules(self):
        """Handle modules list endpoint"""
        modules = get_available_modules()
        self.send_json_response({"modules": modules})
    
    def handle_get_scans(self):
        """Handle scan history endpoint"""
        history = get_scan_history()
        self.send_json_response({"scans": history})
    
    def handle_get_active_scans(self):
        """Handle active scans endpoint"""
        active = get_active_scans()
        self.send_json_response({"active_scans": active})
    
    def handle_get_scan_status(self, scan_id):
        """Handle scan status endpoint"""
        status = get_scan_status(scan_id)
        self.send_json_response(status)
    
    def handle_get_scan_results(self, scan_id):
        """Handle scan results endpoint"""
        results = get_scan_results(scan_id)
        self.send_json_response(results)
    
    def handle_get_scan_findings(self, scan_id):
        """Handle scan findings endpoint"""
        findings = get_findings_data(scan_id)
        self.send_json_response(findings)
    
    def handle_start_scan(self):
        """Handle scan start endpoint"""
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            request_data = json.loads(body)
            
            # Extract parameters
            target = request_data.get("target")
            modules = request_data.get("modules")
            scan_id = request_data.get("scan_id")
            
            if not target:
                self.send_error(400, "Target is required")
                return
            
            # Start scan in background (simplified for demo)
            scan_data = execute_scan_with_progress(target, modules, scan_id)
            
            response = {
                "scan_id": scan_data["scan_id"],
                "status": "started",
                "target": target,
                "modules": modules or ENHANCED_MODULES,
                "created_at": scan_data["created_at"]
            }
            
            self.send_json_response(response)
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON in request body")
        except Exception as e:
            self.send_error(500, f"Failed to start scan: {str(e)}")
    
    def send_json_response(self, data):
        """Send JSON response"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_cors_headers()
        self.end_headers()
        
        response_json = json.dumps(data, indent=2)
        self.wfile.write(response_json.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Custom logging format"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {format % args}")

def start_server():
    """Start the ARGUS HTTP server"""
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, ArgusRequestHandler)
    
    print(f"🚀 ARGUS Server starting on http://{HOST}:{PORT}")
    print(f"📋 Available endpoints:")
    print(f"   GET  /api/health - Health check")
    print(f"   GET  /api/modules - List available modules")
    print(f"   GET  /api/scans - Get scan history")
    print(f"   GET  /api/scans/active - Get active scans")
    print(f"   GET  /api/scan/{'{scan_id}'} - Get scan status")
    print(f"   GET  /api/scan/{'{scan_id}'}?results=1 - Get scan results")
    print(f"   GET  /api/scan/{'{scan_id}'}?findings=1 - Get scan findings")
    print(f"   POST /api/scan - Start new scan")
    print(f"")
    print(f"🔧 Enhanced modules: {len(ENHANCED_MODULES)}")
    print(f"📊 Active scans: {len(active_scans)}")
    print(f"📚 Scan history: {len(scan_history)}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n🛑 Server stopped by user")
        httpd.server_close()

if __name__ == "__main__":
    start_server() 