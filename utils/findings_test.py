# utils/findings_test.py
"""
Testing utility for the centralized findings system
Standalone version for utils directory
"""

import json
import os
import sys
from datetime import datetime

# Add parent directory to path so we can import config modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

print(f"📁 Path setup:")
print(f"   Current directory: {current_dir}")
print(f"   Parent directory: {parent_dir}")
print(f"   Python path: {sys.path[:3]}...")

try:
    from config.findings_rules import evaluate_findings, FINDINGS_RULES
    print("✅ Successfully imported findings_rules")
except ImportError as e:
    print(f"❌ Error importing findings_rules: {e}")
    print("Please ensure the following files exist:")
    print("  - config/findings_rules.py")
    print("  - config/findings_config.py") 
    print(f"Looking for config in: {parent_dir}/config/")
    
    # Check if files actually exist
    config_dir = os.path.join(parent_dir, "config")
    if os.path.exists(config_dir):
        print(f"✅ Config directory exists: {config_dir}")
        files = os.listdir(config_dir)
        print(f"📁 Files in config: {files}")
    else:
        print(f"❌ Config directory does not exist: {config_dir}")
    
    sys.exit(1)

def create_test_data():
    """Create test data for all modules"""
    test_cases = {
        "dns_records.py": [
            {
                "name": "minimal_records",
                "data": {
                    "records": [
                        {"type": "A", "name": "example.com", "value": "1.2.3.4"},
                        {"type": "MX", "name": "example.com", "value": "mail.example.com"}
                    ],
                    "status": "SUCCESS"
                },
                "expected_severity": "I",
                "expected_success": True
            },
            {
                "name": "extensive_records",
                "data": {
                    "records": [
                        {"type": "A", "name": f"sub{i}.example.com", "value": "1.2.3.4"} 
                        for i in range(20)
                    ] + [
                        {"type": "TXT", "name": "example.com", "value": "v=spf1 include:_spf.google.com"},
                        {"type": "TXT", "name": "_dmarc.example.com", "value": "v=DMARC1; p=reject"}
                    ],
                    "status": "SUCCESS"
                },
                "expected_severity": "W",
                "expected_success": True
            },
            {
                "name": "admin_subdomains",
                "data": {
                    "records": [
                        {"type": "A", "name": "admin.example.com", "value": "1.2.3.4"},
                        {"type": "A", "name": "test.example.com", "value": "1.2.3.4"},
                        {"type": "A", "name": "dev.example.com", "value": "1.2.3.4"}
                    ],
                    "status": "SUCCESS"
                },
                "expected_severity": "M",
                "expected_success": True
            }
        ],
        
        "open_ports.py": [
            {
                "name": "safe_ports",
                "data": {
                    "open_ports": [80, 443],
                    "scan_completed": True
                },
                "expected_severity": "M",
                "expected_success": True
            },
            {
                "name": "management_ports",
                "data": {
                    "open_ports": [22, 80, 443, 3389],
                    "scan_completed": True
                },
                "expected_severity": "H",
                "expected_success": True
            },
            {
                "name": "database_exposure",
                "data": {
                    "open_ports": [80, 443, 3306, 5432],
                    "scan_completed": True
                },
                "expected_severity": "C",
                "expected_success": True
            },
            {
                "name": "large_attack_surface",
                "data": {
                    "open_ports": list(range(80, 95)) + [443, 8080, 8443],  # 17 ports
                    "scan_completed": True
                },
                "expected_severity": "H",
                "expected_success": True
            }
        ],
        
        "exposed_env_files.py": [
            {
                "name": "no_exposure",
                "data": {
                    "accessible_files": [],
                    "scan_completed": True
                },
                "expected_severity": "C",  # Base severity
                "expected_success": True
            },
            {
                "name": "files_exposed",
                "data": {
                    "accessible_files": [
                        {
                            "filename": ".env",
                            "analysis": {
                                "sensitive_items": ["API_KEY=secret123", "DB_PASSWORD=pass456"],
                                "risk_level": "CRITICAL"
                            }
                        }
                    ],
                    "scan_completed": True
                },
                "expected_severity": "C",
                "expected_success": True
            }
        ],
        
        "virustotal_scan.py": [
            {
                "name": "clean_domain",
                "data": {
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "scan_completed": True
                },
                "expected_severity": "M",
                "expected_success": True
            },
            {
                "name": "suspicious_domain",
                "data": {
                    "malicious_count": 0,
                    "suspicious_count": 3,
                    "scan_completed": True
                },
                "expected_severity": "H",
                "expected_success": True
            },
            {
                "name": "malicious_domain",
                "data": {
                    "malicious_count": 2,
                    "suspicious_count": 1,
                    "scan_completed": True
                },
                "expected_severity": "C",
                "expected_success": True
            }
        ]
    }
    
    return test_cases

def run_findings_tests():
    """Run comprehensive tests for the findings system"""
    print("\n🧪 Testing Centralized Findings System")
    print("=" * 50)
    
    test_cases = create_test_data()
    total_tests = 0
    passed_tests = 0
    
    for module_name, cases in test_cases.items():
        print(f"\n📋 Testing {module_name}")
        print("-" * 30)
        
        for case in cases:
            total_tests += 1
            test_name = case["name"]
            test_data = case["data"]
            expected_severity = case["expected_severity"]
            expected_success = case["expected_success"]
            
            # Run the evaluation
            result = evaluate_findings(module_name, test_data)
            
            # Check results
            severity_match = result["severity"] == expected_severity
            success_match = result["success"] == expected_success
            
            if severity_match and success_match:
                print(f"  ✅ {test_name}: PASS")
                passed_tests += 1
            else:
                print(f"  ❌ {test_name}: FAIL")
                print(f"     Expected: severity={expected_severity}, success={expected_success}")
                print(f"     Got: severity={result['severity']}, success={result['success']}")
                if result["findings"]:
                    print(f"     Findings: {result['findings']}")
    
    # Summary
    print(f"\n📊 Test Results")
    print("=" * 30)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    return passed_tests == total_tests

def test_individual_module(module_name, test_data):
    """Test a specific module with custom data"""
    print(f"🔍 Testing {module_name}")
    print("-" * 30)
    
    result = evaluate_findings(module_name, test_data)
    
    print(f"Success: {result['success']}")
    print(f"Severity: {result['severity']} ({result['category']})")
    print(f"Title: {result['title']}")
    
    if result["findings"]:
        print(f"Findings ({result['findings_count']}):")
        for finding in result["findings"]:
            print(f"  • {finding}")
    else:
        print("No findings detected")
    
    print(f"Risk Weight: {result.get('total_weight', 0):.1f}")
    print(f"Rules Triggered: {result.get('rules_triggered', 0)}")
    
    return result

def validate_rules_configuration():
    """Validate that all rules are properly configured"""
    print("\n🔧 Validating Rules Configuration")
    print("=" * 40)
    
    errors = []
    warnings = []
    
    for module_name, config in FINDINGS_RULES.items():
        # Check required fields
        required_fields = ["base_severity", "category", "title", "success_criteria", "rules"]
        for field in required_fields:
            if field not in config:
                errors.append(f"{module_name}: Missing required field '{field}'")
        
        # Check severity values
        if config.get("base_severity") not in ["C", "H", "M", "W", "I"]:
            errors.append(f"{module_name}: Invalid base_severity '{config.get('base_severity')}'")
        
        # Check rules
        for i, rule in enumerate(config.get("rules", [])):
            if not hasattr(rule, "condition"):
                errors.append(f"{module_name}: Rule {i} missing condition function")
            if not hasattr(rule, "severity"):
                errors.append(f"{module_name}: Rule {i} missing severity")
            elif rule.severity not in ["C", "H", "M", "W", "I"]:
                errors.append(f"{module_name}: Rule {i} invalid severity '{rule.severity}'")
        
        # Check success criteria
        success_criteria = config.get("success_criteria", [])
        if not success_criteria:
            warnings.append(f"{module_name}: No success criteria defined")
        
        for i, criterion in enumerate(success_criteria):
            if not callable(criterion):
                errors.append(f"{module_name}: Success criterion {i} is not callable")
    
    # Report results
    if errors:
        print("❌ Configuration Errors:")
        for error in errors:
            print(f"  • {error}")
    
    if warnings:
        print("⚠️  Configuration Warnings:")
        for warning in warnings:
            print(f"  • {warning}")
    
    if not errors and not warnings:
        print("✅ Configuration is valid!")
    
    print(f"\nModules configured: {len(FINDINGS_RULES)}")
    print(f"Total rules: {sum(len(config.get('rules', [])) for config in FINDINGS_RULES.values())}")
    
    return len(errors) == 0

def setup_directory_structure():
    """Create the necessary directory structure if it doesn't exist"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    config_dir = os.path.join(project_root, "config")
    
    print(f"\n📁 Project structure check:")
    print(f"   Current directory: {current_dir}")
    print(f"   Project root: {project_root}")
    print(f"   Config directory: {config_dir}")
    
    # Check if config directory exists
    if not os.path.exists(config_dir):
        print(f"⚠️  Config directory doesn't exist: {config_dir}")
        return False
    else:
        print(f"✅ Config directory exists: {config_dir}")
    
    # Check for required files
    required_files = [
        ("config/findings_rules.py", "Core findings rules"),
        ("config/findings_config.py", "Configuration settings"),
    ]
    
    missing_files = []
    for file_path, description in required_files:
        full_path = os.path.join(project_root, file_path)
        if os.path.exists(full_path):
            print(f"✅ Found: {file_path}")
        else:
            print(f"❌ Missing: {file_path} ({description})")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️  Missing {len(missing_files)} required files:")
        for file_path in missing_files:
            print(f"   • {file_path}")
        return False
    else:
        print(f"\n✅ All required files found!")
        return True

def generate_test_report():
    """Generate a comprehensive test report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        report = {
            "timestamp": timestamp,
            "validation_results": validate_rules_configuration(),
            "test_results": run_findings_tests(),
            "configuration_summary": {
                "total_modules": len(FINDINGS_RULES),
                "total_rules": sum(len(config.get("rules", [])) for config in FINDINGS_RULES.values()),
                "categories": list(set(config["category"] for config in FINDINGS_RULES.values())),
                "severity_distribution": {
                    severity: len([c for c in FINDINGS_RULES.values() if c["base_severity"] == severity])
                    for severity in ["C", "H", "M", "W", "I"]
                }
            }
        }
        
        # Save report
        report_file = f"test_report_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n📄 Test report saved to: {report_file}")
        return report
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        return None

if __name__ == "__main__":
    # Check directory structure first
    if not setup_directory_structure():
        print("\n❌ Setup incomplete. Please create the missing files.")
        sys.exit(1)
    
    # Run all tests
    print("\n🚀 Starting Findings System Tests")
    print("=" * 50)
    
    try:
        # Validate configuration
        config_valid = validate_rules_configuration()
        
        if config_valid:
            # Run tests
            tests_passed = run_findings_tests()
            
            # Generate report
            generate_test_report()
            
            if tests_passed:
                print("\n🎉 All tests passed! System ready for deployment.")
            else:
                print("\n⚠️  Some tests failed. Please review the results.")
        else:
            print("\n❌ Configuration validation failed. Please fix errors before testing.")
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()