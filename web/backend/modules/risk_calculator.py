# web/backend/modules/risk_calculator.py
"""
Risk Assessment Calculator
Calculates risk scores and assessments based on security findings
"""

from .module_mappings import CATEGORY_WEIGHTS, SEVERITY_SCORES
import math

class RiskCalculator:
    def __init__(self):
        self.max_risk_score = 100
        self.risk_thresholds = {
            'critical': 80,
            'high': 60,
            'medium': 40,
            'low': 20
        }
    
    def calculate_overall_risk_score(self, findings):
        """
        Calculate overall risk score (0-100) based on findings
        
        Args:
            findings (list): List of security findings
            
        Returns:
            int: Risk score from 0-100
        """
        if not findings:
            return 0
        
        # Calculate weighted score
        total_weighted_score = 0
        total_weight = 0
        
        for finding in findings:
            category = finding.get('category', '')
            severity = finding.get('severity', 'low')
            
            category_weight = CATEGORY_WEIGHTS.get(category, 0.5)
            severity_score = SEVERITY_SCORES.get(severity, 1)
            
            weighted_score = category_weight * severity_score
            total_weighted_score += weighted_score
            total_weight += category_weight
        
        # Normalize to 0-100 scale
        if total_weight == 0:
            return 0
        
        average_weighted_score = total_weighted_score / total_weight
        
        # Scale to 0-100 (max theoretical score is 10)
        risk_score = min(100, int((average_weighted_score / 10) * 100))
        
        # Apply finding count multiplier for many findings
        finding_multiplier = min(1.2, 1 + (len(findings) - 1) * 0.02)
        risk_score = min(100, int(risk_score * finding_multiplier))
        
        return risk_score
    
    def get_risk_level_from_score(self, score):
        """Convert numeric score to risk level"""
        if score >= self.risk_thresholds['critical']:
            return 'critical'
        elif score >= self.risk_thresholds['high']:
            return 'high'
        elif score >= self.risk_thresholds['medium']:
            return 'medium'
        elif score >= self.risk_thresholds['low']:
            return 'low'
        else:
            return 'minimal'
    
    def calculate_risk_assessment(self, findings):
        """
        Calculate comprehensive risk assessment
        
        Args:
            findings (list): List of security findings
            
        Returns:
            dict: Comprehensive risk assessment
        """
        if not findings:
            return {
                'overall_score': 0,
                'risk_level': 'minimal',
                'total_findings': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0,
                'affected_categories': [],
                'top_risks': [],
                'remediation_priority': []
            }
        
        # Count findings by severity
        severity_counts = {
            'critical': len([f for f in findings if f.get('severity') == 'critical']),
            'high': len([f for f in findings if f.get('severity') == 'high']),
            'medium': len([f for f in findings if f.get('severity') == 'medium']),
            'low': len([f for f in findings if f.get('severity') == 'low'])
        }
        
        # Calculate overall score
        overall_score = self.calculate_overall_risk_score(findings)
        risk_level = self.get_risk_level_from_score(overall_score)
        
        # Get affected categories
        affected_categories = list(set(f.get('category', '') for f in findings))
        
        # Identify top risks (critical and high severity findings)
        top_risks = []
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        high_findings = [f for f in findings if f.get('severity') == 'high']
        
        # Add top critical findings
        for finding in sorted(critical_findings, key=lambda x: CATEGORY_WEIGHTS.get(x.get('category', ''), 0), reverse=True)[:3]:
            top_risks.append({
                'title': finding.get('title', ''),
                'severity': finding.get('severity', ''),
                'category': finding.get('category', ''),
                'business_impact': finding.get('business_impact', '')
            })
        
        # Add top high findings if we have room
        for finding in sorted(high_findings, key=lambda x: CATEGORY_WEIGHTS.get(x.get('category', ''), 0), reverse=True):
            if len(top_risks) < 5:
                top_risks.append({
                    'title': finding.get('title', ''),
                    'severity': finding.get('severity', ''),
                    'category': finding.get('category', ''),
                    'business_impact': finding.get('business_impact', '')
                })
        
        # Generate remediation priority
        remediation_priority = self._generate_remediation_priority(findings)
        
        return {
            'overall_score': overall_score,
            'risk_level': risk_level,
            'total_findings': len(findings),
            'critical_findings': severity_counts['critical'],
            'high_findings': severity_counts['high'],
            'medium_findings': severity_counts['medium'],
            'low_findings': severity_counts['low'],
            'severity_distribution': severity_counts,
            'affected_categories': affected_categories,
            'top_risks': top_risks,
            'remediation_priority': remediation_priority,
            'risk_factors': self._analyze_risk_factors(findings)
        }
    
    def get_category_breakdown(self, findings):
        """
        Get detailed breakdown by category
        
        Args:
            findings (list): List of security findings
            
        Returns:
            dict: Category-wise breakdown
        """
        category_breakdown = {}
        
        for finding in findings:
            category = finding.get('category', 'Unknown')
            
            if category not in category_breakdown:
                category_breakdown[category] = {
                    'finding_count': 0,
                    'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                    'risk_score': 0,
                    'findings': []
                }
            
            # Count this finding
            category_breakdown[category]['finding_count'] += 1
            severity = finding.get('severity', 'low')
            category_breakdown[category]['severity_counts'][severity] += 1
            category_breakdown[category]['findings'].append(finding)
        
        # Calculate category risk scores
        for category, data in category_breakdown.items():
            category_findings = data['findings']
            data['risk_score'] = self._calculate_category_risk_score(category_findings, category)
            data['risk_level'] = self.get_risk_level_from_score(data['risk_score'])
            data['category_weight'] = CATEGORY_WEIGHTS.get(category, 0.5)
        
        # Sort by risk score descending
        sorted_categories = dict(sorted(category_breakdown.items(), 
                                      key=lambda x: x[1]['risk_score'], 
                                      reverse=True))
        
        return sorted_categories
    
    def _calculate_category_risk_score(self, findings, category):
        """Calculate risk score for a specific category"""
        if not findings:
            return 0
        
        category_weight = CATEGORY_WEIGHTS.get(category, 0.5)
        
        # Calculate average severity score for the category
        total_severity_score = sum(SEVERITY_SCORES.get(f.get('severity', 'low'), 1) for f in findings)
        average_severity = total_severity_score / len(findings)
        
        # Apply category weight and finding count multiplier
        finding_multiplier = min(1.3, 1 + (len(findings) - 1) * 0.05)
        category_score = category_weight * average_severity * finding_multiplier
        
        # Scale to 0-100
        return min(100, int((category_score / 10) * 100))
    
    def _generate_remediation_priority(self, findings):
        """Generate prioritized remediation recommendations"""
        priorities = []
        
        # Group findings by category and severity
        critical_by_category = {}
        high_by_category = {}
        
        for finding in findings:
            category = finding.get('category', 'Unknown')
            severity = finding.get('severity', 'low')
            
            if severity == 'critical':
                if category not in critical_by_category:
                    critical_by_category[category] = []
                critical_by_category[category].append(finding)
            elif severity == 'high':
                if category not in high_by_category:
                    high_by_category[category] = []
                high_by_category[category].append(finding)
        
        # Priority 1: Critical Information Disclosure
        if 'Information Disclosure' in critical_by_category:
            priorities.append({
                'priority': 'Immediate',
                'timeframe': '24-48 hours',
                'action': 'Address Critical Data Exposure',
                'description': 'Immediately secure exposed sensitive data, credentials, and configuration files',
                'finding_count': len(critical_by_category['Information Disclosure'])
            })
        
        # Priority 2: Critical Security Threats
        threat_categories = ['Threat Intelligence', 'Attack Surface Expansion']
        critical_threats = sum(len(critical_by_category.get(cat, [])) for cat in threat_categories)
        if critical_threats > 0:
            priorities.append({
                'priority': 'Urgent',
                'timeframe': '1-3 days',
                'action': 'Mitigate Active Security Threats',
                'description': 'Address malware, phishing, and critical vulnerabilities',
                'finding_count': critical_threats
            })
        
        # Priority 3: High-severity findings
        total_high = sum(len(findings) for findings in high_by_category.values())
        if total_high > 0:
            priorities.append({
                'priority': 'High',
                'timeframe': '1-2 weeks',
                'action': 'Strengthen Security Configuration',
                'description': 'Fix high-severity security misconfigurations and vulnerabilities',
                'finding_count': total_high
            })
        
        # Priority 4: Medium and low findings
        medium_low_count = len([f for f in findings if f.get('severity') in ['medium', 'low']])
        if medium_low_count > 0:
            priorities.append({
                'priority': 'Medium',
                'timeframe': '1-3 months',
                'action': 'Improve Overall Security Posture',
                'description': 'Address remaining security improvements and best practices',
                'finding_count': medium_low_count
            })
        
        return priorities
    
    def _analyze_risk_factors(self, findings):
        """Analyze key risk factors"""
        risk_factors = {
            'data_exposure_risk': False,
            'active_threats': False,
            'configuration_issues': False,
            'large_attack_surface': False,
            'compliance_concerns': False
        }
        
        # Check for data exposure
        data_exposure_categories = ['Information Disclosure']
        if any(f.get('category') in data_exposure_categories and f.get('severity') in ['critical', 'high'] 
               for f in findings):
            risk_factors['data_exposure_risk'] = True
        
        # Check for active threats
        if any(f.get('category') == 'Threat Intelligence' and f.get('severity') in ['critical', 'high'] 
               for f in findings):
            risk_factors['active_threats'] = True
        
        # Check for configuration issues
        config_categories = ['Security Configuration']
        config_issues = [f for f in findings if f.get('category') in config_categories]
        if len(config_issues) > 3:
            risk_factors['configuration_issues'] = True
        
        # Check for large attack surface
        surface_categories = ['Attack Surface Expansion', 'Network & Infrastructure']
        surface_findings = [f for f in findings if f.get('category') in surface_categories]
        if len(surface_findings) > 5:
            risk_factors['large_attack_surface'] = True
        
        # Check for compliance concerns
        if any(f.get('category') == 'Compliance & Privacy' and f.get('severity') in ['medium', 'high'] 
               for f in findings):
            risk_factors['compliance_concerns'] = True
        
        return risk_factors
    
    def generate_risk_summary(self, findings):
        """Generate executive risk summary"""
        if not findings:
            return {
                'summary': 'No security findings identified during assessment.',
                'risk_level': 'minimal',
                'key_points': ['Assessment completed successfully', 'No immediate security concerns identified']
            }
        
        risk_assessment = self.calculate_risk_assessment(findings)
        overall_score = risk_assessment['overall_score']
        risk_level = risk_assessment['risk_level']
        
        # Generate summary based on risk level
        if risk_level == 'critical':
            summary = f"Critical security risks identified (Risk Score: {overall_score}/100). Immediate action required to address {risk_assessment['critical_findings']} critical findings across {len(risk_assessment['affected_categories'])} security domains."
        elif risk_level == 'high':
            summary = f"High security risks detected (Risk Score: {overall_score}/100). Urgent attention needed for {risk_assessment['high_findings'] + risk_assessment['critical_findings']} high-priority findings."
        elif risk_level == 'medium':
            summary = f"Moderate security risks present (Risk Score: {overall_score}/100). {risk_assessment['total_findings']} findings require attention to improve security posture."
        else:
            summary = f"Low security risks identified (Risk Score: {overall_score}/100). {risk_assessment['total_findings']} minor findings noted for security improvement."
        
        # Generate key points
        key_points = []
        
        if risk_assessment['critical_findings'] > 0:
            key_points.append(f"{risk_assessment['critical_findings']} critical security issues require immediate attention")
        
        if risk_assessment['high_findings'] > 0:
            key_points.append(f"{risk_assessment['high_findings']} high-severity vulnerabilities identified")
        
        if 'Information Disclosure' in risk_assessment['affected_categories']:
            key_points.append("Sensitive data exposure risks detected")
        
        if 'Threat Intelligence' in risk_assessment['affected_categories']:
            key_points.append("Active security threats or reputation issues identified")
        
        key_points.append(f"Security assessment covered {len(risk_assessment['affected_categories'])} security domains")
        
        return {
            'summary': summary,
            'risk_level': risk_level,
            'risk_score': overall_score,
            'key_points': key_points[:5]  # Limit to top 5 points
        }