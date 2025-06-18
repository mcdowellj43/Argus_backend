# web/backend/modules/module_mappings.py
"""
Module to Finding Mappings
Maps each of the 54 Argus modules to their corresponding security findings
"""

MODULE_FINDINGS_MAP = {
    # Information Disclosure Category (Critical Risk)
    'data_leak.py': {
        'category': 'Information Disclosure',
        'base_severity': 'critical',
        'title': 'Data Breach Exposure Detected',
        'description': 'Email addresses or credentials associated with the target have been found in known data breaches, indicating potential compromise of user accounts or organizational data.',
        'business_impact': 'Direct data breach risk, potential regulatory compliance violations, credential theft enabling unauthorized access',
        'recommendation': 'Implement continuous breach monitoring, notify affected users, mandate password resets for compromised accounts, and enhance authentication security'
    },
    
    'exposed_env_files.py': {
        'category': 'Information Disclosure',
        'base_severity': 'critical',
        'title': 'Configuration Files Publicly Exposed',
        'description': 'Environment configuration files containing potentially sensitive information such as API keys, database credentials, or internal settings are publicly accessible.',
        'business_impact': 'Direct exposure of secrets and credentials, potential unauthorized access to internal systems and databases',
        'recommendation': 'Immediately remove exposed configuration files, rotate any exposed secrets, implement proper access controls, and audit deployment processes'
    },
    
    'pastebin_monitoring.py': {
        'category': 'Information Disclosure',
        'base_severity': 'high',
        'title': 'Sensitive Data Found in Paste Sites',
        'description': 'Organizational data, credentials, or sensitive information has been identified on public paste sites like Pastebin, indicating potential data leakage.',
        'business_impact': 'Sensitive information publicly available, potential insider threats or accidental data exposure',
        'recommendation': 'Monitor paste sites continuously, remove sensitive content where possible, investigate source of leakage, and implement data loss prevention measures'
    },
    
    'email_harvester.py': {
        'category': 'Information Disclosure',
        'base_severity': 'medium',
        'title': 'Email Addresses Publicly Discoverable',
        'description': 'Employee email addresses are easily discoverable through public sources, enabling targeted phishing attacks and social engineering campaigns.',
        'business_impact': 'Increased susceptibility to phishing attacks, social engineering, and targeted spam campaigns',
        'recommendation': 'Implement email obfuscation techniques, provide security awareness training, and consider using contact forms instead of direct email exposure'
    },
    
    'archive_history.py': {
        'category': 'Information Disclosure',
        'base_severity': 'medium',
        'title': 'Historical Data Exposure in Archives',
        'description': 'Sensitive information from previous versions of the website has been preserved in web archives and may still be accessible.',
        'business_impact': 'Historical sensitive data remains accessible, potential exposure of deprecated but still sensitive information',
        'recommendation': 'Review archived content for sensitive information, request removal from archive services where necessary, and ensure current data governance practices'
    },

    # Attack Surface Expansion Category (High Risk)
    'subdomain_enum.py': {
        'category': 'Attack Surface Expansion',
        'base_severity': 'high',
        'title': 'Additional Subdomains Discovered',
        'description': 'Multiple subdomains have been identified, expanding the potential attack surface and providing additional entry points for attackers.',
        'business_impact': 'Increased attack surface, potential discovery of forgotten or poorly secured services, unauthorized access opportunities',
        'recommendation': 'Audit all discovered subdomains, disable unnecessary services, ensure consistent security policies across all subdomains, and implement subdomain monitoring'
    },
    
    'subdomain_takeover.py': {
        'category': 'Attack Surface Expansion',
        'base_severity': 'critical',
        'title': 'Subdomain Takeover Vulnerability',
        'description': 'One or more subdomains are vulnerable to takeover attacks due to dangling DNS records pointing to unclaimed external services.',
        'business_impact': 'Complete subdomain compromise, potential phishing attacks using legitimate domain, brand reputation damage',
        'recommendation': 'Immediately remove dangling DNS records, claim any abandoned external services, implement DNS monitoring, and establish subdomain lifecycle management'
    },
    
    'open_ports.py': {
        'category': 'Attack Surface Expansion',
        'base_severity': 'high',
        'title': 'Open Network Services Detected',
        'description': 'Multiple network services are accessible from the internet, potentially providing entry points for unauthorized access attempts.',
        'business_impact': 'Increased attack vectors, potential unauthorized access to internal services, service enumeration opportunities for attackers',
        'recommendation': 'Review necessity of all open ports, close unnecessary services, implement proper firewall rules, and ensure all exposed services are properly secured'
    },
    
    'content_discovery.py': {
        'category': 'Attack Surface Expansion',
        'base_severity': 'medium',
        'title': 'Hidden Content and Directories Found',
        'description': 'Administrative interfaces, backup files, or sensitive directories that are not intended for public access have been discovered.',
        'business_impact': 'Potential access to administrative functions, exposure of sensitive files, information leakage about internal structure',
        'recommendation': 'Secure or remove unnecessary exposed content, implement proper access controls, disable directory listing, and review web server configuration'
    },
    
    'directory_finder.py': {
        'category': 'Attack Surface Expansion',
        'base_severity': 'medium',
        'title': 'Directory Structure Enumerable',
        'description': 'The website\'s directory structure can be systematically enumerated, revealing the organization and layout of web resources.',
        'business_impact': 'Information disclosure about site structure, potential discovery of administrative areas, reconnaissance advantage for attackers',
        'recommendation': 'Disable directory browsing, implement custom error pages, restrict access to administrative directories, and review web server security configuration'
    },
    
    'associated_hosts.py': {
        'category': 'Attack Surface Expansion',
        'base_severity': 'medium',
        'title': 'Related Domains and Hosts Identified',
        'description': 'Additional domains and hosts associated with the organization have been identified, potentially sharing security vulnerabilities or misconfigurations.',
        'business_impact': 'Extended attack surface across multiple domains, potential lateral movement opportunities, shared infrastructure risks',
        'recommendation': 'Ensure consistent security policies across all related domains, audit security posture of all identified hosts, and implement centralized security management'
    },
    
    'port_scanner.py': {
        'category': 'Attack Surface Expansion',
        'base_severity': 'high',
        'title': 'Network Port Scanning Results',
        'description': 'Comprehensive port scanning has revealed the network services landscape, identifying both expected and potentially unexpected open services.',
        'business_impact': 'Complete visibility of network attack surface, potential discovery of forgotten services, service fingerprinting opportunities',
        'recommendation': 'Validate necessity of all identified services, implement network segmentation, ensure proper service hardening, and establish regular port scanning audits'
    },

    # Security Configuration Category (High Risk)
    'ssl_labs_report.py': {
        'category': 'Security Configuration',
        'base_severity': 'high',
        'title': 'SSL/TLS Configuration Assessment',
        'description': 'SSL/TLS configuration analysis reveals potential weaknesses in cryptographic implementation, certificate management, or protocol support.',
        'business_impact': 'Potential man-in-the-middle attacks, data interception, compromised data in transit, compliance violations',
        'recommendation': 'Update SSL/TLS configuration to current best practices, disable weak ciphers, ensure proper certificate management, and implement HSTS'
    },
    
    'http_security.py': {
        'category': 'Security Configuration',
        'base_severity': 'medium',
        'title': 'HTTP Security Headers Analysis',
        'description': 'Analysis of HTTP security headers reveals missing or misconfigured security controls that protect against common web attacks.',
        'business_impact': 'Increased vulnerability to XSS, clickjacking, MITM attacks, and other web-based threats',
        'recommendation': 'Implement comprehensive security headers including HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy'
    },
    
    'http_headers.py': {
        'category': 'Security Configuration',
        'base_severity': 'low',
        'title': 'HTTP Response Headers Reviewed',
        'description': 'HTTP response headers have been analyzed for security-relevant information and potential information disclosure.',
        'business_impact': 'Potential information leakage about server technology, minor security configuration insights',
        'recommendation': 'Review server headers for information disclosure, implement security headers, and consider header obfuscation for sensitive applications'
    },
    
    'firewall_detection.py': {
        'category': 'Security Configuration',
        'base_severity': 'medium',
        'title': 'Web Application Firewall Analysis',
        'description': 'Web Application Firewall (WAF) presence and configuration have been analyzed, providing insights into perimeter security controls.',
        'business_impact': 'Understanding of perimeter security posture, potential bypass opportunities if WAF is misconfigured',
        'recommendation': 'Ensure WAF is properly configured and monitoring all relevant traffic, regularly update WAF rules, and implement logging and alerting'
    },
    
    'ssl_pinning_check.py': {
        'category': 'Security Configuration',
        'base_severity': 'medium',
        'title': 'SSL Certificate Pinning Assessment',
        'description': 'SSL certificate pinning implementation has been evaluated to determine protection against certificate-based attacks.',
        'business_impact': 'Potential vulnerability to certificate substitution attacks, man-in-the-middle attacks using rogue certificates',
        'recommendation': 'Implement SSL certificate pinning for critical applications, establish certificate monitoring, and plan for certificate rotation procedures'
    },
    
    'certificate_authority_recon.py': {
        'category': 'Security Configuration',
        'base_severity': 'medium',
        'title': 'Certificate Authority Intelligence',
        'description': 'Certificate transparency logs and CA information reveal insights about certificate issuance patterns and potential unauthorized certificates.',
        'business_impact': 'Potential unauthorized certificate issuance, certificate management oversight gaps',
        'recommendation': 'Monitor certificate transparency logs for unauthorized certificates, implement certificate authority authorization (CAA) records, and establish certificate lifecycle management'
    },
    
    'dnssec_check.py': {
        'category': 'Security Configuration',
        'base_severity': 'medium',
        'title': 'DNSSEC Configuration Review',
        'description': 'DNS Security Extensions (DNSSEC) implementation has been evaluated for protection against DNS manipulation attacks.',
        'business_impact': 'Potential DNS spoofing and cache poisoning attacks, domain hijacking vulnerability',
        'recommendation': 'Implement DNSSEC to cryptographically secure DNS responses, monitor DNSSEC validation, and ensure proper key management'
    },
    
    'security_txt.py': {
        'category': 'Security Configuration',
        'base_severity': 'low',
        'title': 'Security.txt Policy Review',
        'description': 'Security.txt file implementation provides insights into the organization\'s vulnerability disclosure and security contact policies.',
        'business_impact': 'Security researcher communication channel assessment, responsible disclosure process evaluation',
        'recommendation': 'Implement or update security.txt file with current contact information, establish clear vulnerability disclosure process, and ensure security team responsiveness'
    },

    # Network & Infrastructure Category (Medium Risk)
    'dns_records.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'DNS Infrastructure Mapping',
        'description': 'DNS records have been enumerated, revealing the domain\'s infrastructure components including mail servers, name servers, and service endpoints.',
        'business_impact': 'Infrastructure reconnaissance information, potential identification of internal services',
        'recommendation': 'Review DNS records for unnecessary information disclosure, ensure proper DNS security practices, and consider using DNS security services'
    },
    
    'whois_lookup.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Domain Registration Information',
        'description': 'Domain registration details including ownership, registration dates, and contact information have been collected from WHOIS databases.',
        'business_impact': 'Organizational information disclosure, potential social engineering target identification',
        'recommendation': 'Consider domain privacy protection, ensure contact information is current and appropriate, monitor domain expiration dates'
    },
    
    'ip_info.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'IP Address Intelligence',
        'description': 'IP address geolocation, ownership, and ISP information has been gathered, providing insights into hosting infrastructure.',
        'business_impact': 'Infrastructure reconnaissance, hosting provider identification, geographic location disclosure',
        'recommendation': 'Ensure hosting infrastructure aligns with business requirements, consider geographic and jurisdictional implications of hosting choices'
    },
    
    'server_location.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Server Geographic Location',
        'description': 'Server geographic location and hosting provider information has been identified through various geolocation services.',
        'business_impact': 'Data sovereignty and jurisdiction considerations, infrastructure location disclosure',
        'recommendation': 'Verify server locations align with compliance requirements, consider data residency regulations, and evaluate hosting provider security practices'
    },
    
    'server_info.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'medium',
        'title': 'Server Technology Fingerprinting',
        'description': 'Server technology stack, software versions, and configuration details have been identified through fingerprinting techniques.',
        'business_impact': 'Technology stack disclosure, potential identification of vulnerable software versions',
        'recommendation': 'Implement server header obfuscation, ensure all software is current and patched, consider technology stack hardening'
    },
    
    'mx_records.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Mail Server Configuration',
        'description': 'Mail exchange (MX) records reveal the email infrastructure and mail server configuration for the domain.',
        'business_impact': 'Email infrastructure reconnaissance, potential email security assessment opportunities',
        'recommendation': 'Ensure mail servers are properly secured, implement SPF/DKIM/DMARC records, and monitor email infrastructure for security'
    },
    
    'txt_records.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'DNS TXT Records Analysis',
        'description': 'DNS TXT records have been analyzed, potentially revealing SPF records, domain verification tokens, and other configuration information.',
        'business_impact': 'Configuration information disclosure, potential identification of third-party service integrations',
        'recommendation': 'Review TXT records for sensitive information, ensure proper SPF/DKIM/DMARC configuration, and clean up obsolete verification tokens'
    },
    
    'dns_over_https.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'DNS over HTTPS Configuration',
        'description': 'DNS over HTTPS (DoH) implementation and configuration has been evaluated for privacy and security enhancements.',
        'business_impact': 'DNS privacy and security posture assessment, potential DNS monitoring and filtering bypass capabilities',
        'recommendation': 'Consider implementing DNS over HTTPS for improved privacy, evaluate impact on network monitoring capabilities'
    },
    
    'traceroute.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Network Path Analysis',
        'description': 'Network routing path to the target has been traced, revealing intermediate network infrastructure and potential network topology.',
        'business_impact': 'Network infrastructure reconnaissance, routing path disclosure, potential identification of network security controls',
        'recommendation': 'Ensure network infrastructure is properly secured, consider impact of network topology disclosure on security posture'
    },

    # Web Application Analysis Category (Medium Risk)
    'technology_stack.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'medium',
        'title': 'Technology Stack Identification',
        'description': 'Web application technology stack including frameworks, content management systems, and software versions has been identified.',
        'business_impact': 'Technology stack disclosure enabling targeted attacks, potential identification of vulnerable software versions',
        'recommendation': 'Implement technology obfuscation, ensure all software components are current and patched, regularly audit technology stack for vulnerabilities'
    },
    
    'cms_detection.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'medium',
        'title': 'Content Management System Detection',
        'description': 'Content Management System (CMS) type, version, and configuration details have been identified through fingerprinting techniques.',
        'business_impact': 'CMS-specific attack vectors, potential exploitation of known CMS vulnerabilities, plugin and theme security risks',
        'recommendation': 'Keep CMS updated to latest version, audit and update all plugins/themes, implement CMS-specific security hardening measures'
    },
    
    'robots_txt.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'low',
        'title': 'Robots.txt File Analysis',
        'description': 'Robots.txt file has been analyzed for directory disclosure and crawler directives that may reveal sensitive areas of the website.',
        'business_impact': 'Potential disclosure of administrative or sensitive directories, unintended information about site structure',
        'recommendation': 'Review robots.txt for sensitive directory disclosure, ensure disallowed directories are properly secured, consider alternative crawler control methods'
    },
    
    'sitemap.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'low',
        'title': 'XML Sitemap Analysis',
        'description': 'XML sitemap has been parsed to identify all publicly listed pages and site structure information.',
        'business_impact': 'Complete site structure reconnaissance, identification of all public pages, potential discovery of forgotten or sensitive pages',
        'recommendation': 'Review sitemap for sensitive page disclosure, ensure sitemap only includes intended public content, implement proper access controls'
    },
    
    'crawler.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'medium',
        'title': 'Website Crawling Results',
        'description': 'Systematic website crawling has discovered additional pages, resources, and potential entry points not immediately visible.',
        'business_impact': 'Comprehensive site structure discovery, potential identification of hidden or forgotten pages, increased attack surface awareness',
        'recommendation': 'Audit all discovered pages for appropriate access controls, remove unnecessary public pages, implement comprehensive security testing'
    },
    
    'broken_links.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'low',
        'title': 'Broken Links and Dead Resources',
        'description': 'Broken links and dead resources have been identified, potentially indicating maintenance issues or forgotten content.',
        'business_impact': 'Poor user experience, potential security implications of broken authentication or authorization links',
        'recommendation': 'Fix broken links, remove references to dead resources, audit link integrity regularly, ensure security-critical links function properly'
    },
    
    'redirect_chain.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'low',
        'title': 'URL Redirect Chain Analysis',
        'description': 'URL redirect chains have been analyzed for security implications, potential open redirects, and redirect loop issues.',
        'business_impact': 'Potential open redirect vulnerabilities, phishing attack vectors, poor user experience from redirect issues',
        'recommendation': 'Validate all redirect destinations, implement whitelist-based redirect controls, audit redirect chains for security issues'
    },
    
    'cookies.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'medium',
        'title': 'Cookie Security Configuration',
        'description': 'HTTP cookies have been analyzed for security attributes including HttpOnly, Secure, SameSite, and expiration settings.',
        'business_impact': 'Potential session hijacking, XSS exploitation through cookie theft, CSRF attack vectors',
        'recommendation': 'Implement proper cookie security attributes, use HttpOnly and Secure flags, implement appropriate SameSite policies'
    },
    
    'social_media.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'low',
        'title': 'Social Media Integration Analysis',
        'description': 'Social media presence and integration with the website has been analyzed for security and privacy implications.',
        'business_impact': 'Social engineering attack surface, potential privacy violations, third-party integration risks',
        'recommendation': 'Audit social media integrations for security, implement privacy controls, monitor social media presence for security issues'
    },
    
    'third_party_integrations.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'medium',
        'title': 'Third-Party Service Integrations',
        'description': 'Third-party services and integrations have been identified, revealing dependencies on external services and potential supply chain risks.',
        'business_impact': 'Supply chain security risks, third-party data sharing implications, dependency on external service security',
        'recommendation': 'Audit all third-party integrations for security, implement vendor risk management, monitor third-party service security posture'
    },

    # Threat Intelligence Category (Critical/High Risk)
    'virustotal_scan.py': {
        'category': 'Threat Intelligence',
        'base_severity': 'high',
        'title': 'Malware and Threat Reputation Analysis',
        'description': 'Domain and IP reputation analysis through VirusTotal reveals potential associations with malicious activity or security threats.',
        'business_impact': 'Potential reputation damage, blacklisting risks, association with malicious infrastructure',
        'recommendation': 'Investigate any malicious detections, implement reputation monitoring, consider IP/domain reputation management services'
    },
    
    'malware_phishing.py': {
        'category': 'Threat Intelligence',
        'base_severity': 'critical',
        'title': 'Malware and Phishing Threat Detection',
        'description': 'Active malware or phishing threats have been detected associated with the target domain or infrastructure.',
        'business_impact': 'Immediate security threat, potential compromise of users and systems, severe reputation damage, legal liability',
        'recommendation': 'Immediately investigate and remediate malware/phishing threats, notify affected users, implement enhanced monitoring, coordinate with security vendors'
    },
    
    'domain_reputation.py': {
        'category': 'Threat Intelligence',
        'base_severity': 'medium',
        'title': 'Domain Reputation Assessment',
        'description': 'Domain reputation analysis across multiple threat intelligence sources reveals the security standing and trustworthiness of the target domain.',
        'business_impact': 'Reputation-based filtering and blocking risks, potential impact on email deliverability and user trust',
        'recommendation': 'Monitor domain reputation continuously, address any reputation issues promptly, implement reputation management practices'
    },
    
    'censys.py': {
        'category': 'Threat Intelligence',
        'base_severity': 'medium',
        'title': 'Internet-Wide Asset Discovery',
        'description': 'Comprehensive internet-wide scanning has identified additional assets, services, and potential security exposures associated with the organization.',
        'business_impact': 'Discovery of forgotten or shadow IT assets, potential exposure of internal services, comprehensive attack surface mapping',
        'recommendation': 'Audit all discovered assets, ensure proper security controls on all identified services, implement asset discovery monitoring'
    },
    
    'shodan.py': {
        'category': 'Threat Intelligence',
        'base_severity': 'high',
        'title': 'Internet-Connected Device Discovery',
        'description': 'Shodan search engine results reveal internet-connected devices and services associated with the organization, potentially including exposed industrial control systems, IoT devices, or misconfigured services.',
        'business_impact': 'Discovery of exposed critical infrastructure, potential unauthorized access to industrial systems, IoT security risks',
        'recommendation': 'Immediately secure any exposed critical systems, implement network segmentation, audit all internet-connected devices, establish IoT security policies'
    },

    # Compliance & Privacy Category (Medium/Low Risk)
    'privacy_gdpr.py': {
        'category': 'Compliance & Privacy',
        'base_severity': 'medium',
        'title': 'Privacy and GDPR Compliance Assessment',
        'description': 'Privacy policy implementation and GDPR compliance measures have been evaluated for data protection and regulatory compliance.',
        'business_impact': 'Potential regulatory compliance violations, privacy law enforcement actions, user trust and legal liability issues',
        'recommendation': 'Ensure full GDPR compliance, implement comprehensive privacy policies, establish data protection officer oversight, conduct privacy impact assessments'
    },
    
    'carbon_footprint.py': {
        'category': 'Compliance & Privacy',
        'base_severity': 'low',
        'title': 'Environmental Impact Assessment',
        'description': 'Website carbon footprint and environmental impact have been assessed, providing insights into sustainability and environmental responsibility.',
        'business_impact': 'Environmental responsibility metrics, potential regulatory compliance in jurisdictions with environmental regulations',
        'recommendation': 'Consider implementing green hosting solutions, optimize website performance for reduced environmental impact, establish sustainability metrics'
    },
    
    'global_ranking.py': {
        'category': 'Compliance & Privacy',
        'base_severity': 'low',
        'title': 'Website Popularity and Ranking Analysis',
        'description': 'Global website ranking and popularity metrics provide insights into the site\'s visibility and potential attractiveness to attackers.',
        'business_impact': 'Attractiveness as an attack target correlates with visibility, higher profile sites require enhanced security measures',
        'recommendation': 'Implement security measures appropriate for site visibility level, consider enhanced monitoring for high-profile sites'
    },
    
    'performance_monitoring.py': {
        'category': 'Compliance & Privacy',
        'base_severity': 'low',
        'title': 'Website Performance Analysis',
        'description': 'Website performance metrics including load times, responsiveness, and user experience factors have been evaluated.',
        'business_impact': 'User experience implications, potential business impact from poor performance, SEO considerations',
        'recommendation': 'Optimize website performance, implement performance monitoring, ensure adequate infrastructure capacity'
    },
    
    'quality_metrics.py': {
        'category': 'Compliance & Privacy',
        'base_severity': 'low',
        'title': 'Website Quality and Standards Assessment',
        'description': 'Website quality metrics including code quality, accessibility, and standards compliance have been evaluated.',
        'business_impact': 'Code quality affects security posture, accessibility compliance requirements, professional reputation',
        'recommendation': 'Implement code quality standards, ensure accessibility compliance, regularly audit website standards adherence'
    }
}

# Category metadata for risk calculation
CATEGORY_WEIGHTS = {
    'Information Disclosure': 1.0,        # Highest risk - direct data exposure
    'Attack Surface Expansion': 0.9,      # Very high risk - more attack vectors
    'Threat Intelligence': 0.9,           # Very high risk - active threats
    'Security Configuration': 0.8,        # High risk - security controls
    'Web Application Analysis': 0.6,      # Medium risk - application security
    'Network & Infrastructure': 0.5,      # Medium risk - infrastructure info
    'Compliance & Privacy': 0.3           # Lower risk - compliance/quality
}

# Severity to numeric score mapping
SEVERITY_SCORES = {
    'critical': 10,
    'high': 7,
    'medium': 4,
    'low': 1
}

def get_module_categories():
    """Get all unique categories"""
    return list(set(mapping['category'] for mapping in MODULE_FINDINGS_MAP.values()))

def get_modules_by_category(category):
    """Get all modules in a specific category"""
    return [module for module, mapping in MODULE_FINDINGS_MAP.items() 
            if mapping['category'] == category]

def get_category_risk_level(category):
    """Get the risk weight for a category"""
    return CATEGORY_WEIGHTS.get(category, 0.5)

def validate_module_mappings():
    """Validate that all required fields are present in mappings"""
    required_fields = ['category', 'base_severity', 'title', 'description', 'business_impact', 'recommendation']
    
    for module_name, mapping in MODULE_FINDINGS_MAP.items():
        for field in required_fields:
            if field not in mapping:
                raise ValueError(f"Missing required field '{field}' in mapping for {module_name}")
        
        if mapping['base_severity'] not in SEVERITY_SCORES:
            raise ValueError(f"Invalid severity '{mapping['base_severity']}' for {module_name}")
        
        if mapping['category'] not in CATEGORY_WEIGHTS:
            raise ValueError(f"Invalid category '{mapping['category']}' for {module_name}")
    
    return True

# Validate mappings on import
try:
    validate_module_mappings()
    print(f"✓ Successfully loaded {len(MODULE_FINDINGS_MAP)} module mappings across {len(get_module_categories())} categories")
except ValueError as e:
    print(f"✗ Module mapping validation failed: {e}")
    raise