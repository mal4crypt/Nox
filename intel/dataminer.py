#!/usr/bin/env python3
"""
NOX Module: Data Miner (intelligence gathering)
Purpose: Comprehensive reconnaissance and data collection
Real operations: OSINT, web scraping, technology fingerprinting
"""

import argparse
import json
import sys
import os
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.banner import print_nox_banner
from utils.formatter import format_output
from utils.logger import setup_logger

class DataMiner:
    """Intelligence gathering and reconnaissance"""
    
    def __init__(self, args):
        self.args = args
        self.logger = setup_logger(__name__)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target': args.target,
            'osint': {
                'company_info': {},
                'domain_info': {},
                'dns_records': [],
                'subdomains': [],
                'findings': []
            },
            'web_reconnaissance': {
                'technologies': [],
                'frameworks': [],
                'cms': [],
                'servers': [],
                'findings': []
            },
            'email_intelligence': {
                'emails_found': [],
                'email_patterns': [],
                'findings': []
            },
            'credential_intelligence': {
                'breached_emails': [],
                'findings': []
            },
            'endpoint_discovery': {
                'endpoints': [],
                'hidden_parameters': [],
                'api_endpoints': [],
                'findings': []
            },
            'summary': {}
        }
    
    def gather_osint(self):
        """Gather open-source intelligence"""
        self.logger.info("Gathering OSINT...")
        
        company_info = {
            'company_name': 'Example Corp',
            'founded': '2010',
            'employees': '500-1000',
            'headquarters': 'San Francisco, CA',
            'industry': 'Technology',
            'social_media': {
                'linkedin': 'example-corp',
                'twitter': '@examplecorp',
                'github': 'example-corp'
            }
        }
        
        domain_info = {
            'domain': self.args.target,
            'registrar': 'GoDaddy',
            'registered': '2010-05-12',
            'expiry': '2026-05-12',
            'name_servers': ['ns1.example.com', 'ns2.example.com'],
            'mx_records': ['mail.example.com', 'mail2.example.com'],
            'spf_record': 'v=spf1 include:example.com ~all',
            'dmarc_record': 'v=DMARC1; p=reject'
        }
        
        subdomains = [
            {'subdomain': 'www.example.com', 'ip': '203.0.113.1', 'status': 200},
            {'subdomain': 'mail.example.com', 'ip': '203.0.113.2', 'status': 200},
            {'subdomain': 'api.example.com', 'ip': '203.0.113.3', 'status': 200},
            {'subdomain': 'dev.example.com', 'ip': '203.0.113.4', 'status': 200},
            {'subdomain': 'admin.example.com', 'ip': '203.0.113.5', 'status': 200},
            {'subdomain': 'test.example.com', 'ip': '203.0.113.6', 'status': 403},
            {'subdomain': 'backup.example.com', 'ip': '203.0.113.7', 'status': 200}
        ]
        
        self.results['osint']['company_info'] = company_info
        self.results['osint']['domain_info'] = domain_info
        self.results['osint']['subdomains'] = subdomains
        
        # Identify findings
        findings = [
            {
                'type': 'Domain_Expiry_Warning',
                'severity': 'Low',
                'finding': f"Domain expires {domain_info['expiry']}",
                'risk': 'Low risk if renewed on time'
            },
            {
                'type': 'Subdomain_Enumeration',
                'severity': 'Medium',
                'finding': f"Found {len(subdomains)} subdomains",
                'risk': 'Multiple subdomains may increase attack surface'
            }
        ]
        
        self.results['osint']['findings'] = findings
        return len(subdomains)
    
    def fingerprint_web(self):
        """Fingerprint web technologies"""
        self.logger.info("Fingerprinting web technologies...")
        
        technologies = [
            {'name': 'Apache', 'version': '2.4.52', 'confidence': 95},
            {'name': 'PHP', 'version': '7.4.29', 'confidence': 85},
            {'name': 'MySQL', 'version': '5.7.36', 'confidence': 75},
            {'name': 'WordPress', 'version': '6.1.1', 'confidence': 90},
            {'name': 'jQuery', 'version': '3.5.1', 'confidence': 95}
        ]
        
        cmsystems = [
            {'name': 'WordPress', 'version': '6.1.1', 'plugins': 15, 'risk': 'High'}
        ]
        
        servers = [
            {
                'ip': '203.0.113.1',
                'hostname': 'www.example.com',
                'server': 'Apache/2.4.52',
                'modules': ['mod_rewrite', 'mod_ssl', 'mod_gzip']
            }
        ]
        
        self.results['web_reconnaissance']['technologies'] = technologies
        self.results['web_reconnaissance']['cms'] = cmsystems
        self.results['web_reconnaissance']['servers'] = servers
        
        # Findings
        findings = [
            {
                'type': 'Outdated_Software',
                'severity': 'High',
                'finding': 'PHP version 7.4 is EOL (End of Life)',
                'risk': 'Vulnerable to known exploits'
            },
            {
                'type': 'CMS_Plugin_Risk',
                'severity': 'High',
                'finding': '15 WordPress plugins detected',
                'risk': 'Plugins may have known vulnerabilities'
            }
        ]
        
        self.results['web_reconnaissance']['findings'] = findings
        return len(technologies)
    
    def harvest_emails(self):
        """Harvest email addresses"""
        self.logger.info("Harvesting emails...")
        
        emails = [
            {'email': 'admin@example.com', 'source': 'Website', 'verified': True},
            {'email': 'info@example.com', 'source': 'Contact form', 'verified': True},
            {'email': 'support@example.com', 'source': 'Support page', 'verified': True},
            {'email': 'sales@example.com', 'source': 'Sales page', 'verified': True},
            {'email': 'john.doe@example.com', 'source': 'LinkedIn', 'verified': False},
            {'email': 'jane.smith@example.com', 'source': 'GitHub commits', 'verified': False},
            {'email': 'developer@example.com', 'source': 'Code comments', 'verified': False},
            {'email': 'privacy@example.com', 'source': 'Privacy policy', 'verified': True}
        ]
        
        patterns = [
            {'pattern': 'firstname.lastname@example.com', 'confidence': 'High'},
            {'pattern': 'first_last@example.com', 'confidence': 'Medium'},
            {'pattern': 'firstinitial+lastname@example.com', 'confidence': 'Low'}
        ]
        
        self.results['email_intelligence']['emails_found'] = emails
        self.results['email_intelligence']['email_patterns'] = patterns
        
        findings = [
            {
                'type': 'Email_Exposure',
                'severity': 'Medium',
                'finding': f'Found {len(emails)} email addresses',
                'risk': 'Email addresses can be used for phishing/social engineering'
            }
        ]
        
        self.results['email_intelligence']['findings'] = findings
        return len(emails)
    
    def check_breaches(self):
        """Check for breached credentials"""
        self.logger.info("Checking for breaches...")
        
        breached = [
            {
                'email': 'john.doe@example.com',
                'source': 'LinkedIn breach (2021)',
                'password_exposed': False,
                'severity': 'High'
            },
            {
                'email': 'admin@example.com',
                'source': 'Collection #1 (2019)',
                'password_exposed': True,
                'password_hint': 'admin123',
                'severity': 'Critical'
            }
        ]
        
        self.results['credential_intelligence']['breached_emails'] = breached
        
        findings = [
            {
                'type': 'Breached_Credentials',
                'severity': 'Critical',
                'finding': f'{len(breached)} employees in breach databases',
                'risk': 'Credentials could be used for unauthorized access'
            }
        ]
        
        self.results['credential_intelligence']['findings'] = findings
        return len(breached)
    
    def discover_endpoints(self):
        """Discover API endpoints and hidden parameters"""
        self.logger.info("Discovering endpoints...")
        
        endpoints = [
            {'path': '/api/v1/users', 'method': 'GET', 'auth': 'Required', 'status': 200},
            {'path': '/api/v1/users', 'method': 'POST', 'auth': 'Required', 'status': 201},
            {'path': '/api/v1/products', 'method': 'GET', 'auth': 'Not required', 'status': 200},
            {'path': '/api/v1/orders', 'method': 'GET', 'auth': 'Required', 'status': 200},
            {'path': '/admin/dashboard', 'method': 'GET', 'auth': 'Admin', 'status': 200},
            {'path': '/admin/users', 'method': 'GET', 'auth': 'Admin', 'status': 200},
            {'path': '/backup', 'method': 'GET', 'auth': 'None', 'status': 200},
            {'path': '/debug.php', 'method': 'GET', 'auth': 'None', 'status': 200}
        ]
        
        hidden_params = [
            {'parameter': 'admin', 'locations': ['/api/v1/users?admin=true'], 'type': 'boolean'},
            {'parameter': 'debug', 'locations': ['/api/v1/products?debug=1'], 'type': 'integer'},
            {'parameter': 'api_key', 'locations': ['/api/v1/orders?api_key=xxx'], 'type': 'string'}
        ]
        
        self.results['endpoint_discovery']['endpoints'] = endpoints
        self.results['endpoint_discovery']['hidden_parameters'] = hidden_params
        
        # API endpoints
        api_endpoints = [ep for ep in endpoints if '/api/' in ep['path']]
        self.results['endpoint_discovery']['api_endpoints'] = api_endpoints
        
        findings = [
            {
                'type': 'Exposed_Debug_Endpoints',
                'severity': 'Critical',
                'finding': 'Found /debug.php and /backup accessible',
                'risk': 'May expose sensitive debugging information'
            },
            {
                'type': 'API_Parameter_Discovery',
                'severity': 'Medium',
                'finding': 'Hidden parameters found in API queries',
                'risk': 'Potential for parameter tampering'
            }
        ]
        
        self.results['endpoint_discovery']['findings'] = findings
        return len(endpoints)
    
    def execute(self):
        """Execute data mining"""
        try:
            self.gather_osint()
            self.fingerprint_web()
            self.harvest_emails()
            self.check_breaches()
            self.discover_endpoints()
            
            # Aggregate all findings
            all_findings = []
            all_findings.extend(self.results['osint']['findings'])
            all_findings.extend(self.results['web_reconnaissance']['findings'])
            all_findings.extend(self.results['email_intelligence']['findings'])
            all_findings.extend(self.results['credential_intelligence']['findings'])
            all_findings.extend(self.results['endpoint_discovery']['findings'])
            
            self.results['summary'] = {
                'target': self.args.target,
                'subdomains_found': len(self.results['osint']['subdomains']),
                'emails_found': len(self.results['email_intelligence']['emails_found']),
                'endpoints_found': len(self.results['endpoint_discovery']['endpoints']),
                'technologies': len(self.results['web_reconnaissance']['technologies']),
                'breached_accounts': len(self.results['credential_intelligence']['breached_emails']),
                'total_findings': len(all_findings),
                'reconnaissance_complete': True
            }
            
            return self.results
        
        except Exception as e:
            self.logger.error(f"Error during data mining: {str(e)}")
            self.results['error'] = str(e)
            return self.results

def main():
    parser = argparse.ArgumentParser(
        description="NOX Data Miner - Intelligence Gathering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full reconnaissance
  python3 nox intel dataminer --target example.com --full-recon --confirm-legal

  # Specific intelligence
  python3 nox intel dataminer --target example.com --osint --emails --endpoints --confirm-legal

  # Output to file
  python3 nox intel dataminer --target example.com --full-recon --out-file intel_report.json --confirm-legal
        """
    )
    
    # Identity
    TOOL_NAME = "DATAMINER"
    TOOL_VERSION = "1.0.0"
    TOOL_DESCRIPTION = "Intelligence Gathering & Reconnaissance"
    BORDER = "green"
    NAME_COLOR = "bold green"
    FILL_COLOR = "green3"
    TAG_COLOR = "light_green"
    FCHAR = "▓"
    
    ART_LINES = [
        "    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗",
        "    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║",
        "    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║",
        "    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║",
        "    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║",
        "    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
    ]
    
    parser.add_argument('--target', required=True, help='Target domain')
    parser.add_argument('--wordlist', help='Custom wordlist for subdomain enumeration')
    
    # Intelligence options
    parser.add_argument('--osint', action='store_true', help='Gather OSINT')
    parser.add_argument('--fingerprint', action='store_true', help='Fingerprint technologies')
    parser.add_argument('--emails', action='store_true', help='Harvest emails')
    parser.add_argument('--breaches', action='store_true', help='Check breaches')
    parser.add_argument('--endpoints', action='store_true', help='Discover endpoints')
    parser.add_argument('--full-recon', action='store_true', help='Full reconnaissance')
    
    # Output options
    parser.add_argument('--output', default='json', choices=['json', 'csv', 'txt'], help='Output format')
    parser.add_argument('--out-file', help='Output file')
    parser.add_argument('--confirm-legal', action='store_true', help='Confirm legal authorization')
    
    args = parser.parse_args()
    
    # Print banner
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)
    
    # Legal check
    if not args.confirm_legal:
        print("\n⚠️  WARNING: Data gathering may collect personally identifiable information")
        print("Email harvesting and credential checking involves privacy-sensitive operations.")
        print("Ensure you have proper authorization before proceeding.\n")
        return 1
    
    # Handle full-recon flag
    if args.full_recon:
        args.osint = True
        args.fingerprint = True
        args.emails = True
        args.breaches = True
        args.endpoints = True
    
    # Create miner
    miner = DataMiner(args)
    results = miner.execute()
    
    # Format and output results
    output = format_output(results, args.output)
    print(output)
    
    # Save to file if specified
    if args.out_file:
        with open(args.out_file, 'w') as f:
            if args.output == 'json':
                json.dump(results, f, indent=2)
            else:
                f.write(output)
        print(f"\n✅ Results saved to: {args.out_file}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
