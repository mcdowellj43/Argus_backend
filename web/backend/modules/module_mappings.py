# web/backend/modules/module_mappings.py
"""
Module to Finding Mappings
Maps each of the 54 Argus modules to their corresponding security findings
"""

MODULE_FINDINGS_MAP = {
    # Network & Infrastructure
    'associated_hosts.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'medium',
        'title': 'Related Domains and Hosts Identified',
        'description': 'Additional domains and hosts associated with the organization have been identified, potentially sharing security vulnerabilities or misconfigurations.',
        'business_impact': 'Extended attack surface across multiple domains, potential lateral movement opportunities, shared infrastructure risks',
        'recommendation': 'Ensure consistent security policies across all related domains, audit security posture of all identified hosts, and implement centralized security management'
    },
    'dns_over_https.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'DNS over HTTPS Configuration',
        'description': 'DNS over HTTPS (DoH) implementation and configuration has been evaluated for privacy and security enhancements.',
        'business_impact': 'DNS privacy and security posture assessment, potential DNS monitoring and filtering bypass capabilities',
        'recommendation': 'Consider implementing DNS over HTTPS for improved privacy, evaluate impact on network monitoring capabilities'
    },
    
    # Web Application Analysis
    'content_discovery.py': {
        'category': 'Web Application Analysis',
        'base_severity': 'medium',
        'title': 'Hidden Content and Directories Found',
        'description': 'Administrative interfaces, backup files, or sensitive directories that are not intended for public access have been discovered.',
        'business_impact': 'Potential access to administrative functions, exposure of sensitive files, information leakage about internal structure',
        'recommendation': 'Secure or remove unnecessary exposed content, implement proper access controls, disable directory listing, and review web server configuration'
    },
    
    # Security & Threat Intelligence
    'data_leak.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'critical',
        'title': 'Data Breach Exposure Detected',
        'description': 'Email addresses or credentials associated with the target have been found in known data breaches, indicating potential compromise of user accounts or organizational data.',
        'business_impact': 'Direct data breach risk, potential regulatory compliance violations, credential theft enabling unauthorized access',
        'recommendation': 'Implement continuous breach monitoring, notify affected users, mandate password resets for compromised accounts, and enhance authentication security'
    },
    'subdomain_takeover.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'critical',
        'title': 'Subdomain Takeover Vulnerability',
        'description': 'One or more subdomains are vulnerable to takeover attacks due to dangling DNS records pointing to unclaimed external services.',
        'business_impact': 'Complete subdomain compromise, potential phishing attacks using legitimate domain, brand reputation damage',
        'recommendation': 'Immediately remove dangling DNS records, claim any abandoned external services, implement DNS monitoring, and establish subdomain lifecycle management'
    },
    
    # Vulnerability Scanning
    'network_vuln_scan.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'critical',
        'title': 'Network Vulnerability Assessment',
        'description': 'Comprehensive network vulnerability scanning has identified critical security weaknesses in network services, including unpatched systems, weak configurations, and exploitable services.',
        'business_impact': 'Direct network compromise risk, unauthorized access to internal systems, potential data breaches and service disruption',
        'recommendation': 'Immediately patch identified vulnerabilities, implement network segmentation, harden service configurations, and establish regular vulnerability scanning'
    },
    
    'exposed_env_files.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'critical',
        'title': 'Configuration Files Publicly Exposed',
        'description': 'Environment configuration files containing potentially sensitive information such as API keys, database credentials, or internal settings are publicly accessible.',
        'business_impact': 'Direct exposure of secrets and credentials, potential unauthorized access to internal systems and databases',
        'recommendation': 'Immediately remove exposed configuration files, rotate any exposed secrets, implement proper access controls, and audit deployment processes'
    },
    
    'pastebin_monitoring.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'high',
        'title': 'Sensitive Data Found in Paste Sites',
        'description': 'Organizational data, credentials, or sensitive information has been identified on public paste sites like Pastebin, indicating potential data leakage.',
        'business_impact': 'Sensitive information publicly available, potential insider threats or accidental data exposure',
        'recommendation': 'Monitor paste sites continuously, remove sensitive content where possible, investigate source of leakage, and implement data loss prevention measures'
    },
    
    'email_harvester.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'medium',
        'title': 'Email Addresses Publicly Discoverable',
        'description': 'Employee email addresses are easily discoverable through public sources, enabling targeted phishing attacks and social engineering campaigns.',
        'business_impact': 'Increased susceptibility to phishing attacks, social engineering, and targeted spam campaigns',
        'recommendation': 'Implement email obfuscation techniques, provide security awareness training, and consider using contact forms instead of direct email exposure'
    },
    
    'archive_history.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'medium',
        'title': 'Historical Data Exposure in Archives',
        'description': 'Sensitive information from previous versions of the website has been preserved in web archives and may still be accessible.',
        'business_impact': 'Historical sensitive data remains accessible, potential exposure of deprecated but still sensitive information',
        'recommendation': 'Review archived content for sensitive information, request removal from archive services where necessary, and ensure current data governance practices'
    },

    'subdomain_enum.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'high',
        'title': 'Additional Subdomains Discovered',
        'description': 'Multiple subdomains have been identified, expanding the potential attack surface and providing additional entry points for attackers.',
        'business_impact': 'Increased attack surface, potential discovery of forgotten or poorly secured services, unauthorized access opportunities',
        'recommendation': 'Audit all discovered subdomains, disable unnecessary services, ensure consistent security policies across all subdomains, and implement subdomain monitoring'
    },
    
    'open_ports.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'high',
        'title': 'Open Network Services Detected',
        'description': 'Multiple network services are accessible from the internet, potentially providing entry points for unauthorized access attempts.',
        'business_impact': 'Increased attack vectors, potential unauthorized access to internal services, service enumeration opportunities for attackers',
        'recommendation': 'Review necessity of all open ports, close unnecessary services, implement proper firewall rules, and ensure all exposed services are properly secured'
    },
    
    'directory_finder.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'medium',
        'title': 'Directory Structure Enumerable',
        'description': 'The website\'s directory structure can be systematically enumerated, revealing the organization and layout of web resources.',
        'business_impact': 'Information disclosure about site structure, potential discovery of administrative areas, reconnaissance advantage for attackers',
        'recommendation': 'Disable directory browsing, implement custom error pages, restrict access to administrative directories, and review web server security configuration'
    },
    
    'port_scanner.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'high',
        'title': 'Network Port Scanning Results',
        'description': 'Comprehensive port scanning has revealed the network services landscape, identifying both expected and potentially unexpected open services.',
        'business_impact': 'Complete visibility of network attack surface, potential discovery of forgotten services, service fingerprinting opportunities',
        'recommendation': 'Validate necessity of all identified services, implement network segmentation, ensure proper service hardening, and establish regular port scanning audits'
    },

    'ssl_labs_report.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'high',
        'title': 'SSL/TLS Configuration Assessment',
        'description': 'SSL/TLS configuration analysis reveals potential weaknesses in cryptographic implementation, certificate management, or protocol support.',
        'business_impact': 'Potential man-in-the-middle attacks, data interception, compromised data in transit, compliance violations',
        'recommendation': 'Update SSL/TLS configuration to current best practices, disable weak ciphers, ensure proper certificate management, and implement HSTS'
    },
    
    'http_security.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'medium',
        'title': 'HTTP Security Headers Analysis',
        'description': 'Analysis of HTTP security headers reveals missing or misconfigured security controls that protect against common web attacks.',
        'business_impact': 'Increased vulnerability to XSS, clickjacking, MITM attacks, and other web-based threats',
        'recommendation': 'Implement comprehensive security headers including HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy'
    },
    
    'http_headers.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'low',
        'title': 'HTTP Response Headers Reviewed',
        'description': 'HTTP response headers have been analyzed for security-relevant information and potential information disclosure.',
        'business_impact': 'Potential information leakage about server technology, minor security configuration insights',
        'recommendation': 'Review server headers for information disclosure, implement security headers, and consider header obfuscation for sensitive applications'
    },
    
    'firewall_detection.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'medium',
        'title': 'Web Application Firewall Analysis',
        'description': 'Web Application Firewall (WAF) presence and configuration have been analyzed, providing insights into perimeter security controls.',
        'business_impact': 'Understanding of perimeter security posture, potential bypass opportunities if WAF is misconfigured',
        'recommendation': 'Ensure WAF is properly configured and monitoring all relevant traffic, regularly update WAF rules, and implement logging and alerting'
    },
    
    'ssl_pinning_check.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'medium',
        'title': 'SSL Certificate Pinning Assessment',
        'description': 'SSL certificate pinning implementation has been evaluated to determine protection against certificate-based attacks.',
        'business_impact': 'Potential vulnerability to certificate substitution attacks, man-in-the-middle attacks using rogue certificates',
        'recommendation': 'Implement SSL certificate pinning for critical applications, establish certificate monitoring, and plan for certificate rotation procedures'
    },
    
    'certificate_authority_recon.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'medium',
        'title': 'Certificate Authority Intelligence',
        'description': 'Certificate transparency logs and CA information reveal insights about certificate issuance patterns and potential unauthorized certificates.',
        'business_impact': 'Potential unauthorized certificate issuance, certificate management oversight gaps',
        'recommendation': 'Monitor certificate transparency logs for unauthorized certificates, implement certificate authority authorization (CAA) records, and establish certificate lifecycle management'
    },
    
    'dnssec_check.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'medium',
        'title': 'DNSSEC Configuration Review',
        'description': 'DNS Security Extensions (DNSSEC) implementation has been evaluated for protection against DNS manipulation attacks.',
        'business_impact': 'Potential DNS spoofing and cache poisoning attacks, domain hijacking vulnerability',
        'recommendation': 'Implement DNSSEC to cryptographically secure DNS responses, monitor DNSSEC validation, and ensure proper key management'
    },
    
    'security_txt.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Security.txt Policy Review',
        'description': 'Security.txt file implementation provides insights into the organization\'s vulnerability disclosure and security contact policies.',
        'business_impact': 'Security researcher communication channel assessment, responsible disclosure process evaluation',
        'recommendation': 'Implement or update security.txt file with current contact information, establish clear vulnerability disclosure process, and ensure security team responsiveness'
    },

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
    
    'traceroute.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Network Path Analysis',
        'description': 'Network routing path to the target has been traced, revealing intermediate network infrastructure and potential network topology.',
        'business_impact': 'Network infrastructure reconnaissance, routing path disclosure, potential identification of network security controls',
        'recommendation': 'Ensure network infrastructure is properly secured, consider impact of network topology disclosure on security posture'
    },

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

    'virustotal_scan.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'high',
        'title': 'Malware and Threat Reputation Analysis',
        'description': 'Domain and IP reputation analysis through VirusTotal reveals potential associations with malicious activity or security threats.',
        'business_impact': 'Potential reputation damage, blacklisting risks, association with malicious infrastructure',
        'recommendation': 'Investigate any malicious detections, implement reputation monitoring, consider IP/domain reputation management services'
    },
    
    'malware_phishing.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'critical',
        'title': 'Malware and Phishing Threat Detection',
        'description': 'Active malware or phishing threats have been detected associated with the target domain or infrastructure.',
        'business_impact': 'Immediate security threat, potential compromise of users and systems, severe reputation damage, legal liability',
        'recommendation': 'Immediately investigate and remediate malware/phishing threats, notify affected users, implement enhanced monitoring, coordinate with security vendors'
    },
    
    'domain_reputation.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'medium',
        'title': 'Domain Reputation Assessment',
        'description': 'Domain reputation analysis across multiple threat intelligence sources reveals the security standing and trustworthiness of the target domain.',
        'business_impact': 'Reputation-based filtering and blocking risks, potential impact on email deliverability and user trust',
        'recommendation': 'Monitor domain reputation continuously, address any reputation issues promptly, implement reputation management practices'
    },
    
    'censys.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'medium',
        'title': 'Internet-Wide Asset Discovery',
        'description': 'Comprehensive internet-wide scanning has identified additional assets, services, and potential security exposures associated with the organization.',
        'business_impact': 'Discovery of forgotten or shadow IT assets, potential exposure of internal services, comprehensive attack surface mapping',
        'recommendation': 'Audit all discovered assets, ensure proper security controls on all identified services, implement asset discovery monitoring'
    },
    
    'shodan.py': {
        'category': 'Security & Threat Intelligence',
        'base_severity': 'high',
        'title': 'Internet-Connected Device Discovery',
        'description': 'Shodan search engine results reveal internet-connected devices and services associated with the organization, potentially including exposed industrial control systems, IoT devices, or misconfigured services.',
        'business_impact': 'Discovery of exposed critical infrastructure, potential unauthorized access to industrial systems, IoT security risks',
        'recommendation': 'Immediately secure any exposed critical systems, implement network segmentation, audit all internet-connected devices, establish IoT security policies'
    },

    'privacy_gdpr.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'medium',
        'title': 'Privacy and GDPR Compliance Assessment',
        'description': 'Privacy policy implementation and GDPR compliance measures have been evaluated for data protection and regulatory compliance.',
        'business_impact': 'Potential regulatory compliance violations, privacy law enforcement actions, user trust and legal liability issues',
        'recommendation': 'Ensure full GDPR compliance, implement comprehensive privacy policies, establish data protection officer oversight, conduct privacy impact assessments'
    },
    
    'carbon_footprint.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Environmental Impact Assessment',
        'description': 'Website carbon footprint and environmental impact have been assessed, providing insights into sustainability and environmental responsibility.',
        'business_impact': 'Environmental responsibility metrics, potential regulatory compliance in jurisdictions with environmental regulations',
        'recommendation': 'Consider implementing green hosting solutions, optimize website performance for reduced environmental impact, establish sustainability metrics'
    },
    
    'global_ranking.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Website Popularity and Ranking Analysis',
        'description': 'Global website ranking and popularity metrics provide insights into the site\'s visibility and potential attractiveness to attackers.',
        'business_impact': 'Attractiveness as an attack target correlates with visibility, higher profile sites require enhanced security measures',
        'recommendation': 'Implement security measures appropriate for site visibility level, consider enhanced monitoring for high-profile sites'
    },
    
    'performance_monitoring.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Website Performance Analysis',
        'description': 'Website performance metrics including load times, responsiveness, and user experience factors have been evaluated.',
        'business_impact': 'User experience implications, potential business impact from poor performance, SEO considerations',
        'recommendation': 'Optimize website performance, implement performance monitoring, ensure adequate infrastructure capacity'
    },
    
    'quality_metrics.py': {
        'category': 'Network & Infrastructure',
        'base_severity': 'low',
        'title': 'Website Quality and Standards Assessment',
        'description': 'Website quality metrics including code quality, accessibility, and standards compliance have been evaluated.',
        'business_impact': 'Code quality affects security posture, accessibility compliance requirements, professional reputation',
        'recommendation': 'Implement code quality standards, ensure accessibility compliance, regularly audit website standards adherence'
    },

    'service_banner_vulns.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'high',
        'title': 'Service Version Vulnerability Analysis',
        'description': 'Service banner analysis has identified known vulnerabilities in specific software versions running on target systems, including outdated services and exploitable configurations.',
        'business_impact': 'Targeted exploitation of known vulnerabilities, potential system compromise, unauthorized access to services',
        'recommendation': 'Update all identified vulnerable services to latest versions, implement version monitoring, establish patch management procedures'
    },
    
    'default_credentials.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'critical',
        'title': 'Default Credential Exposure',
        'description': 'Default, weak, or commonly used credentials have been identified on network services, databases, and administrative interfaces.',
        'business_impact': 'Immediate unauthorized access risk, complete system compromise, potential data theft and service manipulation',
        'recommendation': 'Immediately change all default credentials, implement strong password policies, enable multi-factor authentication, and conduct credential audits'
    },

    'sql_injection_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'critical',
        'title': 'SQL Injection Vulnerabilities Detected',
        'description': 'SQL injection vulnerabilities have been identified in web applications, allowing potential database access, data manipulation, and system compromise.',
        'business_impact': 'Complete database compromise, data theft, unauthorized data manipulation, potential system access',
        'recommendation': 'Implement input validation and parameterized queries, conduct code review for SQL injection patterns, deploy WAF rules, and test all user inputs'
    },
    
    'xss_vulnerability_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'high',
        'title': 'Cross-Site Scripting (XSS) Vulnerabilities',
        'description': 'Cross-Site Scripting vulnerabilities have been detected, allowing potential client-side code execution, session hijacking, and user data theft.',
        'business_impact': 'User session compromise, data theft, malicious script execution, reputation damage',
        'recommendation': 'Implement proper input validation and output encoding, deploy Content Security Policy (CSP), conduct security testing, and sanitize all user inputs'
    },
    
    'web_app_authentication_bypass.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'critical',
        'title': 'Authentication Bypass Vulnerabilities',
        'description': 'Authentication mechanisms have been found vulnerable to bypass techniques, allowing unauthorized access to protected resources and administrative functions.',
        'business_impact': 'Unauthorized access to sensitive data and functions, complete application compromise, potential privilege escalation',
        'recommendation': 'Implement secure authentication mechanisms, conduct penetration testing, deploy session management controls, and audit all authentication flows'
    },
    
    'directory_traversal_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'high',
        'title': 'Directory Traversal Vulnerabilities',
        'description': 'Directory traversal vulnerabilities have been identified, allowing unauthorized access to sensitive system files and directory structures.',
        'business_impact': 'Sensitive file exposure, system information disclosure, potential configuration file access, server compromise',
        'recommendation': 'Implement proper path validation, deploy web application firewalls, conduct security testing, and restrict file system access'
    },
    
    'api_security_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'high',
        'title': 'API Security Vulnerabilities',
        'description': 'API security vulnerabilities have been detected, including authentication bypass, excessive data exposure, and improper access controls.',
        'business_impact': 'Unauthorized API access, data exposure, potential system compromise, API abuse',
        'recommendation': 'Implement proper API authentication and authorization, deploy rate limiting, conduct API security testing, and validate all API endpoints'
    },

    'ssl_vulnerability_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'critical',
        'title': 'SSL/TLS Security Vulnerabilities',
        'description': 'Critical SSL/TLS vulnerabilities have been identified, including weak ciphers, protocol downgrade attacks, and cryptographic weaknesses.',
        'business_impact': 'Man-in-the-middle attacks, data interception, session hijacking, compliance violations',
        'recommendation': 'Update SSL/TLS configuration, disable weak ciphers and protocols, implement HSTS, and conduct regular cryptographic assessments'
    },
    
    'certificate_vulnerabilities.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'high',
        'title': 'Certificate Security Issues',
        'description': 'SSL certificate vulnerabilities have been detected, including weak signature algorithms, expired certificates, and trust chain issues.',
        'business_impact': 'Certificate-based attacks, man-in-the-middle attacks, service disruption, trust issues',
        'recommendation': 'Update certificates, implement certificate monitoring, establish certificate lifecycle management, and conduct regular certificate audits'
    },

    'cms_vulnerability_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'high',
        'title': 'CMS Security Vulnerabilities',
        'description': 'Content Management System vulnerabilities have been identified, including outdated core installations, vulnerable plugins, and insecure configurations.',
        'business_impact': 'CMS compromise, website defacement, data theft, malware distribution',
        'recommendation': 'Update CMS core and all plugins, remove unused plugins, implement security hardening, and conduct regular CMS security audits'
    },
    
    'file_upload_vulnerabilities.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'critical',
        'title': 'File Upload Security Vulnerabilities',
        'description': 'File upload functionality has been found vulnerable to malicious file uploads, allowing potential code execution and system compromise.',
        'business_impact': 'Remote code execution, system compromise, malware upload, data theft',
        'recommendation': 'Implement strict file type validation, deploy antivirus scanning, restrict upload directories, and conduct security testing'
    },

    'cloud_misconfig_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'high',
        'title': 'Cloud Security Misconfigurations',
        'description': 'Cloud service misconfigurations have been identified, including exposed storage buckets, insecure containers, and improper access controls.',
        'business_impact': 'Data exposure, unauthorized access, compliance violations, potential data breaches',
        'recommendation': 'Review and fix cloud configurations, implement least privilege access, deploy security monitoring, and conduct cloud security audits'
    },
    
    'database_exposure_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'critical',
        'title': 'Database Exposure Vulnerabilities',
        'description': 'Database exposure vulnerabilities have been detected, including unauthenticated access, weak configurations, and sensitive data exposure.',
        'business_impact': 'Complete data compromise, data theft, unauthorized access, compliance violations',
        'recommendation': 'Secure database access, implement authentication, encrypt sensitive data, deploy database firewalls, and conduct security audits'
    },
    
    'email_server_vulnerabilities.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'high',
        'title': 'Email Server Security Vulnerabilities',
        'description': 'Email server vulnerabilities have been identified, including open relay configurations, weak authentication, and exploitable mail server software.',
        'business_impact': 'Email spoofing, spam relay, unauthorized access, reputation damage',
        'recommendation': 'Secure email server configuration, implement authentication, deploy anti-spam measures, and conduct regular security testing'
    },

    'deserialization_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'critical',
        'title': 'Unsafe Deserialization Vulnerabilities',
        'description': 'Unsafe deserialization vulnerabilities have been detected, allowing potential remote code execution and system compromise.',
        'business_impact': 'Remote code execution, system compromise, data manipulation, complete application takeover',
        'recommendation': 'Implement secure deserialization practices, validate all serialized data, deploy security controls, and conduct penetration testing'
    },
    
    'command_injection_scanner.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'critical',
        'title': 'Command Injection Vulnerabilities',
        'description': 'Command injection vulnerabilities have been identified, allowing potential system command execution and complete server compromise.',
        'business_impact': 'System compromise, unauthorized access, data theft, service disruption',
        'recommendation': 'Implement input validation, use parameterized commands, deploy security controls, and conduct comprehensive security testing'
    },
    
    'business_logic_vulnerabilities.py': {
        'category': 'Vulnerability Scanning',
        'base_severity': 'high',
        'title': 'Business Logic Vulnerabilities',
        'description': 'Business logic vulnerabilities have been detected, including race conditions, workflow bypass, and access control flaws.',
        'business_impact': 'Unauthorized access, data manipulation, financial loss, business process compromise',
        'recommendation': 'Conduct business logic testing, implement proper access controls, deploy monitoring, and conduct security code reviews'
    }
}

# Category metadata for risk calculation
CATEGORY_WEIGHTS = {
    'Network & Infrastructure': 1.0,
    'Web Application Analysis': 1.0,
    'Security & Threat Intelligence': 1.0,
    'Vulnerability Scanning': 1.0
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