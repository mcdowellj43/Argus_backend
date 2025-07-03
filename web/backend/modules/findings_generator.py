# web/backend/modules/findings_generator.py
"""
Success-Based Findings Generator
Converts successful module executions into security findings
"""

from .module_mappings import MODULE_FINDINGS_MAP
from .risk_calculator import RiskCalculator
import json
from datetime import datetime

class FindingsGenerator:
    def __init__(self):
        self.risk_calculator = RiskCalculator()
    
    def generate_findings_from_results(self, module_results, target=None):
        """
        Convert successful module results into security findings
        
        Args:
            module_results (list): List of module execution results
            target (str): Target domain/IP being assessed
            
        Returns:
            dict: {
                'findings': [],
                'risk_assessment': {},
                'category_breakdown': {},
                'overall_risk_score': int,
                'summary': {}
            }
        """
        findings = []
        executed_modules = []
        
        # Process each module result
        for result in module_results:
            if self._is_successful_execution(result):
                finding = self._create_finding_from_module(result, target)
                if finding:
                    findings.append(finding)
                    executed_modules.append(result['module_name'])
        
        # Calculate risk assessment
        risk_assessment = self.risk_calculator.calculate_risk_assessment(findings)
        category_breakdown = self.risk_calculator.get_category_breakdown(findings)
        overall_risk_score = self.risk_calculator.calculate_overall_risk_score(findings)
        
        # Generate summary
        summary = self._generate_summary(findings, executed_modules, target)
        
        return {
            'findings': findings,
            'risk_assessment': risk_assessment,
            'category_breakdown': category_breakdown,
            'overall_risk_score': overall_risk_score,
            'summary': summary,
            'generated_at': datetime.now().isoformat()
        }
    
    def _is_successful_execution(self, result):
        """Check if module execution was successful"""
        return (
            result.get('status') in ['completed', 'success'] and
            result.get('output') and 
            len(result.get('output', '')) > 10  # Has meaningful output
        )
    
    def _create_finding_from_module(self, result, target):
        """Create a security finding from a successful module result"""
        module_name = result.get('module_name', '')
        
        # Get finding template from mappings
        finding_template = MODULE_FINDINGS_MAP.get(module_name)
        if not finding_template:
            return None
        
        # Enhance severity based on output analysis
        enhanced_severity = self._analyze_output_severity(result, finding_template['base_severity'])
        
        # Create the finding
        finding = {
            'id': f"{module_name}_{int(datetime.now().timestamp())}",
            'title': finding_template['title'],
            'category': finding_template['category'],
            'severity': enhanced_severity,
            'base_severity': finding_template['base_severity'],
            'description': finding_template['description'],
            'business_impact': finding_template['business_impact'],
            'recommendation': finding_template['recommendation'],
            'module_source': module_name,
            'execution_time': result.get('execution_time', 0),
            'output_preview': self._create_output_preview(result.get('output', '')),
            'details': self._extract_technical_details(result, finding_template),
            'target': target,
            'discovered_at': datetime.now().isoformat()
        }
        
        return finding
    
    def _analyze_output_severity(self, result, base_severity):
        """Enhance severity based on output content analysis"""
        output = result.get('output', '').lower()
        output_lines = len(output.split('\n'))
        
        module_name = result.get('module_name', '')
        
        # Critical escalation conditions
        if any(keyword in output for keyword in ['password', 'secret', 'api_key', 'token', 'credential']):
            return 'critical'
        
        # Module-specific severity enhancement
        if module_name == 'data_leak.py':
            if output_lines > 10 or '@' in output:
                return 'critical'
        elif module_name == 'open_ports.py':
            if output_lines > 15:  # Many open ports
                return 'high'
        elif module_name == 'subdomain_enum.py':
            if output_lines > 20:  # Many subdomains
                return 'high'
        elif module_name in ['malware_phishing.py', 'virustotal_scan.py']:
            if 'malicious' in output or 'infected' in output:
                return 'critical'
        
        return base_severity
    
    def _create_output_preview(self, output):
        """Create a safe preview of module output"""
        if not output:
            return "No output captured"
        
        # Truncate and sanitize output
        preview = output.strip()[:300]
        
        # Count significant findings
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        significant_lines = [line for line in lines if len(line) > 10]
        
        if len(significant_lines) > 5:
            preview += f"\n\n[...and {len(significant_lines) - 5} more results]"
        
        return preview
    
    def _extract_technical_details(self, result, finding_template):
        """Extract relevant technical details based on module type"""
        output = result.get('output', '')
        module_name = result.get('module_name', '')
        
        details = {
            'execution_status': result.get('status'),
            'execution_time_seconds': result.get('execution_time', 0),
            'output_length': len(output),
            'findings_count': len([line for line in output.split('\n') if line.strip()])
        }
        
        # Module-specific detail extraction
        if 'subdomain' in module_name:
            subdomains = [line.strip() for line in output.split('\n') if '.' in line.strip()]
            details['subdomains_found'] = len(subdomains)
            details['sample_subdomains'] = subdomains[:5]
        
        elif 'ports' in module_name:
            # Extract port numbers
            import re
            ports = re.findall(r'\b(\d{1,5})\b', output)
            details['ports_found'] = len(set(ports))
            details['open_ports'] = list(set(ports))[:10]
        
        elif 'email' in module_name:
            # Count email addresses
            import re
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', output)
            details['emails_found'] = len(set(emails))
        
        elif 'ssl' in module_name or 'certificate' in module_name:
            details['certificate_issues'] = 'issues detected' if result.get('error') else 'configuration analyzed'
        
        return details
    
    def _generate_summary(self, findings, executed_modules, target):
        """Generate executive summary of findings"""
        if not findings:
            return {
                'total_findings': 0,
                'risk_level': 'low',
                'key_concerns': [],
                'modules_executed': len(executed_modules),
                'target': target
            }
        
        # Count findings by severity
        severity_counts = {}
        categories = set()
        
        for finding in findings:
            severity = finding['severity']
            category = finding['category']
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            categories.add(category)
        
        # Determine overall risk level
        if severity_counts.get('critical', 0) > 0:
            risk_level = 'critical'
        elif severity_counts.get('high', 0) > 2:
            risk_level = 'high'
        elif severity_counts.get('high', 0) > 0 or severity_counts.get('medium', 0) > 3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Identify key concerns
        key_concerns = []
        critical_findings = [f for f in findings if f['severity'] == 'critical']
        high_findings = [f for f in findings if f['severity'] == 'high']
        
        for finding in critical_findings[:3]:  # Top 3 critical
            key_concerns.append(f"Critical: {finding['title']}")
        
        for finding in high_findings[:3]:  # Top 3 high
            if len(key_concerns) < 5:
                key_concerns.append(f"High: {finding['title']}")
        
        return {
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'categories_affected': list(categories),
            'risk_level': risk_level,
            'key_concerns': key_concerns,
            'modules_executed': len(executed_modules),
            'modules_with_findings': len(findings),
            'target': target
        }