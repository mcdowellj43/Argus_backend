import json
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

# Add the current directory to Python path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Now import from local modules
from config import (
    ENHANCED_MODULES, get_module_timeout, FINDINGS_ENABLED, argus_root,
    MODULE_WEIGHTS, SEVERITY_MULTIPLIERS, MODULE_METADATA
)

# In-memory storage for scans
active_scans = {}
scan_history = {}

# =============================================================================
# ENHANCED MODULE EXECUTION WITH NEW STANDARDIZED FORMAT SUPPORT
# =============================================================================

def execute_module_with_clean_output(module_script, target, scan_id):
    """Execute a module and return enhanced standardized output"""
    start_time = time.time()
    module_path = argus_root / "modules" / module_script
    
    result = {
        "module_name": module_script,
        "target": target,
        "scan_id": scan_id,
        "start_time": datetime.now().isoformat(),
        "status": "UNKNOWN",
        "execution_time": 0,
        "output": "",
        "error": None,
        "data": None,
        "findings": None,  # NEW: Enhanced findings data
        "count": 0,
        "severity": "I",
        "enhanced_module": module_script in ENHANCED_MODULES  # NEW: Track enhanced modules
    }
    
    try:
        if not module_path.exists():
            result["status"] = "ERROR"
            result["error"] = f"Module file not found: {module_script}"
            return result
        
        print(f"🔍 Executing {module_script} with target: {target}")
        
        # Execute module and capture output
        timeout = get_module_timeout(module_script)
        process = subprocess.run(
            [sys.executable, str(module_path), target],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(argus_root)
        )
        
        execution_time = time.time() - start_time
        result["execution_time"] = round(execution_time, 2)
        
        # Capture raw output for legacy compatibility
        result["output"] = process.stdout
        
        if process.stderr:
            result["error"] = process.stderr
        
        # NEW: Try to parse enhanced standardized output first
        if process.returncode == 0:
            if module_script in ENHANCED_MODULES:
                enhanced_data = parse_enhanced_module_output(process.stdout, module_script)
                if enhanced_data:
                    # Module uses new standardized format
                    result.update(enhanced_data)
                    print(f"✅ Enhanced module {module_script}: {result['status']} with findings system")
                else:
                    # Enhanced module but failed to parse - fallback
                    legacy_data = parse_legacy_module_output(process.stdout, module_script)
                    result.update(legacy_data)
                    print(f"⚠️  Enhanced module {module_script} used legacy output")
            else:
                # Legacy module
                legacy_data = parse_legacy_module_output(process.stdout, module_script)
                result.update(legacy_data)
                print(f"ℹ️  Legacy module {module_script}: {result['status']}")
        else:
            result["status"] = "ERROR"
            
    except subprocess.TimeoutExpired:
        result["status"] = "TIMEOUT"
        result["error"] = f"Module execution timed out after {timeout}s"
        result["execution_time"] = timeout
        
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        result["execution_time"] = time.time() - start_time
    
    return result

def parse_enhanced_module_output(output, module_script):
    """Parse new standardized JSON output from enhanced modules"""
    try:
        lines = output.strip().split('\n')
        
        # Look for JSON return data (usually at the end of output)
        for line in reversed(lines):
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                try:
                    json_data = json.loads(line)
                    
                    # Validate it's our standardized format
                    if all(key in json_data for key in ['status', 'data', 'findings', 'execution_time', 'target']):
                        # Extract enhanced data
                        enhanced_result = {
                            "status": json_data.get("status", "UNKNOWN"),
                            "data": json_data.get("data", {}),
                            "findings": json_data.get("findings", {}),
                            "execution_time": json_data.get("execution_time", 0),
                            "target": json_data.get("target", ""),
                            "error": json_data.get("error")
                        }
                        
                        # Extract findings information
                        findings_data = json_data.get("findings", {})
                        if findings_data:
                            enhanced_result["count"] = len(findings_data.get("findings", []))
                            enhanced_result["severity"] = findings_data.get("severity", "I")
                            enhanced_result["has_findings"] = findings_data.get("has_findings", False)
                        else:
                            enhanced_result["count"] = 0
                            enhanced_result["severity"] = "I"
                            enhanced_result["has_findings"] = False
                        
                        return enhanced_result
                        
                except json.JSONDecodeError:
                    continue
        
        return None  # No valid enhanced format found
        
    except Exception as e:
        print(f"⚠️  Error parsing enhanced output for {module_script}: {e}")
        return None

def parse_legacy_module_output(output, module_script):
    """Parse traditional module output (fallback for non-enhanced modules)"""
    try:
        # Count findings using traditional methods
        count = count_findings_in_output(output)
        
        # Determine status based on output patterns
        if "[E] ERROR" in output or "[E] FAILED" in output:
            status = "ERROR"
        elif "[T] TIMEOUT" in output:
            status = "TIMEOUT"
        elif "[I] NO DATA" in output or count == 0:
            status = "NO_DATA"
        elif output.strip():
            status = "SUCCESS"
        else:
            status = "NO_DATA"
        
        # Determine severity based on traditional logic
        severity = determine_module_severity(module_script, count)
        
        return {
            "status": status,
            "count": count,
            "severity": severity,
            "data": {"legacy_output": output},  # Wrap legacy output
            "findings": None,  # No enhanced findings available
            "has_findings": count > 0
        }
        
    except Exception as e:
        print(f"⚠️  Error parsing legacy output for {module_script}: {e}")
        return {
            "status": "ERROR",
            "count": 0,
            "severity": "I",
            "data": {},
            "findings": None,
            "has_findings": False
        }

# =============================================================================
# ENHANCED SCAN AGGREGATION WITH FINDINGS SUPPORT
# =============================================================================

def aggregate_scan_findings(scan_results):
    """Aggregate findings data across all modules in a scan"""
    module_results = scan_results.get("module_results", [])
    
    aggregated = {
        "total_modules": len(module_results),
        "enhanced_modules": 0,
        "legacy_modules": 0,
        "total_findings": 0,
        "findings_by_severity": {"C": 0, "H": 0, "W": 0, "I": 0, "E": 0},
        "findings_by_category": {},
        "overall_risk_score": 0,
        "overall_severity": "I",
        "enhanced_findings": [],
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
    }
    
    total_weighted_score = 0
    total_weight = 0
    
    for module_result in module_results:
        # Track module types
        if module_result.get("enhanced_module", False):
            aggregated["enhanced_modules"] += 1
        else:
            aggregated["legacy_modules"] += 1
        
        # Count findings
        count = module_result.get("count", 0)
        severity = module_result.get("severity", "I")
        
        aggregated["total_findings"] += count
        aggregated["findings_by_severity"][severity] += count
        
        # Map severity to summary format
        severity_mapping = {
            "C": "critical",
            "H": "high", 
            "W": "medium",
            "I": "low",
            "E": "info"
        }
        summary_key = severity_mapping.get(severity, "info")
        aggregated["summary"][summary_key] += count
        
        # Process enhanced findings
        findings_data = module_result.get("findings")
        if findings_data and module_result.get("enhanced_module"):
            # Add to enhanced findings list
            enhanced_finding = {
                "module": module_result.get("module_name"),
                "status": module_result.get("status"),
                "severity": severity,
                "findings_count": count,
                "findings": findings_data,
                "execution_time": module_result.get("execution_time", 0)
            }
            aggregated["enhanced_findings"].append(enhanced_finding)
            
            # Calculate weighted risk score for enhanced modules
            weight = get_module_weight(module_result.get("module_name", ""))
            module_score = count * get_severity_multiplier(severity)
            total_weighted_score += module_score * weight
            total_weight += weight
    
    # Calculate overall risk score
    if total_weight > 0:
        aggregated["overall_risk_score"] = round(total_weighted_score / total_weight, 2)
    else:
        # Fallback calculation for legacy modules
        aggregated["overall_risk_score"] = calculate_legacy_risk_score(aggregated["summary"])
    
    # Determine overall severity
    aggregated["overall_severity"] = determine_overall_severity(aggregated["findings_by_severity"])
    
    return aggregated

def get_module_weight(module_name):
    """Get importance weight for a module"""
    return MODULE_WEIGHTS.get(module_name, 3.0)  # Default weight

def get_severity_multiplier(severity):
    """Get numerical multiplier for severity levels"""
    return SEVERITY_MULTIPLIERS.get(severity, 1.0)

def determine_overall_severity(findings_by_severity):
    """Determine overall scan severity based on findings distribution"""
    if findings_by_severity.get("C", 0) > 0:
        return "C"
    elif findings_by_severity.get("H", 0) > 0:
        return "H"
    elif findings_by_severity.get("W", 0) > 0:
        return "W"
    elif findings_by_severity.get("I", 0) > 0:
        return "I"
    else:
        return "I"

def calculate_legacy_risk_score(summary):
    """Calculate risk score for legacy modules without enhanced findings"""
    score = 0
    score += summary.get("critical", 0) * 10
    score += summary.get("high", 0) * 7
    score += summary.get("medium", 0) * 4
    score += summary.get("low", 0) * 1
    return min(score, 100)  # Cap at 100

# =============================================================================
# ENHANCED API RESPONSE FORMATTING
# =============================================================================

def format_enhanced_scan_response(scan_data):
    """Format scan data with enhanced findings information"""
    # Get base scan data
    base_response = {
        "scan_id": scan_data.get("scan_id"),
        "target": scan_data.get("target"),
        "status": scan_data.get("status"),
        "created_at": scan_data.get("created_at"),
        "completed_at": scan_data.get("completed_at"),
        "total_execution_time": scan_data.get("total_execution_time", 0),
        "enhanced_output": True
    }
    
    # Add aggregated findings data
    findings_summary = aggregate_scan_findings(scan_data)
    base_response.update({
        "findings_summary": findings_summary,
        "module_results": scan_data.get("module_results", []),
        "enhanced_modules_count": findings_summary["enhanced_modules"],
        "legacy_modules_count": findings_summary["legacy_modules"],
        "total_findings": findings_summary["total_findings"],
        "overall_risk_score": findings_summary["overall_risk_score"],
        "overall_severity": findings_summary["overall_severity"]
    })
    
    return base_response

def format_findings_for_frontend(scan_data):
    """Format findings data specifically for frontend consumption"""
    findings_summary = aggregate_scan_findings(scan_data)
    
    formatted_findings = {
        "summary": {
            "total_findings": findings_summary["total_findings"],
            "risk_score": findings_summary["overall_risk_score"],
            "severity": findings_summary["overall_severity"],
            "categories": findings_summary["findings_by_category"],
            "by_severity": findings_summary["summary"]
        },
        "enhanced_findings": findings_summary["enhanced_findings"],
        "module_breakdown": []
    }
    
    # Add module breakdown for frontend display
    for module_result in scan_data.get("module_results", []):
        module_info = {
            "name": module_result.get("module_name"),
            "status": module_result.get("status"),
            "enhanced": module_result.get("enhanced_module", False),
            "findings_count": module_result.get("count", 0),
            "severity": module_result.get("severity", "I"),
            "execution_time": module_result.get("execution_time", 0),
            "has_findings": module_result.get("has_findings", False)
        }
        
        # Add enhanced findings details if available
        if module_result.get("findings") and module_result.get("enhanced_module"):
            findings_data = module_result.get("findings")
            module_info["enhanced_details"] = {
                "success": findings_data.get("success", True),
                "findings": findings_data.get("findings", []),
                "category": findings_data.get("category", "Unknown"),
                "title": findings_data.get("title", ""),
                "risk_weight": findings_data.get("total_weight", 0)
            }
        
        formatted_findings["module_breakdown"].append(module_info)
    
    return formatted_findings

# =============================================================================
# LEGACY COMPATIBILITY FUNCTIONS
# =============================================================================

def count_findings_in_output(output):
    """Count findings in traditional module output"""
    if not output:
        return 0
    
    # Count different types of findings indicators
    critical_count = output.count('[C]')
    high_count = output.count('[H]')
    warning_count = output.count('[W]')
    success_count = output.count('[S]')
    
    # Simple heuristic for total findings
    total = critical_count + high_count + warning_count + success_count
    
    # Alternative counting methods for different output formats
    if total == 0:
        # Try counting "found" indicators
        found_indicators = ['found', 'detected', 'discovered', 'identified']
        for indicator in found_indicators:
            total += output.lower().count(indicator)
        
        # Limit to reasonable number
        total = min(total, 50)
    
    return total

def determine_module_severity(module_script, count):
    """Determine severity based on module type and finding count"""
    if count == 0:
        return "I"
    
    # High-risk modules
    high_risk_modules = [
        'subdomain_takeover.py', 'virustotal_scan.py', 'data_leak.py',
        'exposed_env_files.py', 'pastebin_monitoring.py'
    ]
    
    # Medium-risk modules  
    medium_risk_modules = [
        'content_discovery.py', 'open_ports.py', 'shodan.py',
        'subdomain_enum.py', 'technology_stack.py'
    ]
    
    if module_script in high_risk_modules:
        return "H" if count > 0 else "I"
    elif module_script in medium_risk_modules:
        return "W" if count > 5 else "I"
    else:
        return "I"

def calculate_risk_score(scan_results):
    """Calculate overall risk score for a scan"""
    findings_summary = aggregate_scan_findings(scan_results)
    return findings_summary.get("overall_risk_score", 0)

def determine_risk_level(risk_score):
    """Determine risk level from numerical score"""
    if risk_score >= 8:
        return "HIGH"
    elif risk_score >= 5:
        return "MEDIUM"  
    elif risk_score >= 2:
        return "LOW"
    else:
        return "MINIMAL"

# =============================================================================
# ENHANCED DATA FORMATTING FOR FRONTEND TEMPLATES
# =============================================================================

def get_finding_metadata(module_name):
    """Get metadata for findings from module mappings"""
    return MODULE_METADATA.get(module_name, {
        'category': 'General',
        'base_severity': 'low', 
        'title': 'Security Assessment',
        'description': 'Security assessment completed',
        'business_impact': 'Assessment findings require review',
        'recommendation': 'Review findings and implement security measures'
    })

def format_evidence_for_report(module_result):
    """Format evidence from module results for reports"""
    if not module_result:
        return "No evidence available"
    
    # For enhanced modules, extract structured evidence
    if module_result.get("enhanced_module") and module_result.get("findings"):
        findings_data = module_result.get("findings", {})
        findings_list = findings_data.get("findings", [])
        
        if findings_list:
            evidence = f"Enhanced findings ({len(findings_list)}):"
            for i, finding in enumerate(findings_list[:5], 1):  # Limit to 5
                evidence += f"\n{i}. {finding}"
            if len(findings_list) > 5:
                evidence += f"\n... and {len(findings_list) - 5} more findings"
            return evidence
    
    # For legacy modules, use basic output
    output = module_result.get("output", "")
    if output:
        # Extract key lines from output
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        evidence_lines = [line for line in lines if any(indicator in line for indicator in ['[S]', '[W]', '[H]', '[C]'])]
        
        if evidence_lines:
            return "\n".join(evidence_lines[:10])  # Limit to 10 lines
        else:
            return output[:500] + "..." if len(output) > 500 else output
    
    return "No evidence available"

# =============================================================================
# PROGRESS CALCULATION FOR MONITOR TAB
# =============================================================================

def calculate_scan_progress(scan_data):
    """Calculate scan progress and completion statistics for frontend"""
    if not scan_data:
        return scan_data
    
    # Get module results and total modules
    module_results = scan_data.get("module_results", [])
    modules_list = scan_data.get("modules", [])
    total_modules = len(modules_list)
    
    # Count completed modules (any status except "running" or "queued")
    completed_statuses = ["SUCCESS", "ERROR", "TIMEOUT", "NO_DATA", "FAILED"]
    completed_modules = len([r for r in module_results if r.get("status") in completed_statuses])
    
    # Calculate progress percentage
    if total_modules > 0:
        progress = (completed_modules / total_modules) * 100
    else:
        progress = 0 if scan_data.get("status") == "running" else 100
    
    # Add calculated fields to scan data
    scan_data.update({
        "total_modules": total_modules,
        "completed_modules": completed_modules,
        "progress": round(progress, 1),
        "remaining_modules": total_modules - completed_modules,
    })
    
    # Add current module if scan is running
    if scan_data.get("status") == "running" and completed_modules < total_modules:
        if completed_modules < len(modules_list):
            scan_data["current_module"] = modules_list[completed_modules]
        else:
            scan_data["current_module"] = None
    else:
        scan_data["current_module"] = None
    
    return scan_data 