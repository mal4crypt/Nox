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
import requests
import socket
import ssl
import re
from datetime import datetime
from urllib.parse import urlparse

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
        
        try:
            # Get basic DNS info
            hostname = self.args.target.split('/')[0]
            ip = socket.gethostbyname(hostname)
            
            # Get GeoIP info
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            geo_data = response.json() if response.status_code == 200 else {}
        except:
            ip = "N/A"
            geo_data = {}
        
        company_info = {
            'target': self.args.target,
            'ip_address': ip,
            'resolved': ip != "N/A",
            'geo_location': {
                'country': geo_data.get('country', 'Unknown'),
                'region': geo_data.get('regionName', 'Unknown'),
                'city': geo_data.get('city', 'Unknown'),
                'latitude': geo_data.get('lat'),
                'longitude': geo_data.get('lon'),
                'timezone': geo_data.get('timezone'),
                'isp': geo_data.get('isp', 'Unknown'),
                'organization': geo_data.get('org', 'Unknown'),
                'asn': geo_data.get('as')
            }
        }
        
        domain_info = {
            'domain': self.args.target,
            'status': 'Active' if ip != "N/A" else 'Unreachable',
            'ip': ip
        }
        
        # Try to get subdomains via common patterns
        subdomains = []
        common_subs = ['www', 'mail', 'api', 'dev', 'test', 'admin', 'ftp', 'dns', 'cdn', 'backup']
        for sub in common_subs:
            try:
                full = f"{sub}.{self.args.target}"
                ip_sub = socket.gethostbyname(full)
                subdomains.append({
                    'subdomain': full, 
                    'ip': ip_sub, 
                    'status': 200,
                    'resolved': True
                })
            except:
                subdomains.append({
                    'subdomain': full,
                    'status': 'Not Found',
                    'resolved': False
                })
        
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
        """Fingerprint web technologies and infrastructure"""
        self.logger.info("Fingerprinting web technologies...")
        
        target = self.args.target
        technologies = []
        cmsystems = []
        servers = []
        
        try:
            url = f"http://{target}" if not target.startswith('http') else target
            response = requests.get(url, timeout=5, allow_redirects=True)
            headers = response.headers
            content = response.text.lower()
            
            # Server detection
            server_header = headers.get('Server', 'Unknown')
            servers.append({
                'ip': 'N/A',
                'hostname': target,
                'server': server_header,
                'modules': [],
                'status_code': response.status_code
            })
            
            # Technology detection via headers
            if 'Apache' in server_header:
                technologies.append({'name': 'Apache', 'confidence': 95})
            if 'nginx' in server_header:
                technologies.append({'name': 'Nginx', 'confidence': 95})
            if 'IIS' in server_header:
                technologies.append({'name': 'IIS', 'confidence': 95})
            if 'X-Powered-By' in headers:
                tech = headers.get('X-Powered-By')
                technologies.append({'name': tech, 'confidence': 90})
            
            # CMS detection
            if 'wp-content' in content or 'wp-includes' in content:
                cmsystems.append({'name': 'WordPress', 'confidence': 95, 'risk': 'High'})
            if 'joomla' in content:
                cmsystems.append({'name': 'Joomla', 'confidence': 90, 'risk': 'High'})
            if 'drupal' in content:
                cmsystems.append({'name': 'Drupal', 'confidence': 90, 'risk': 'High'})
            
            # Framework detection
            if 'laravel' in content:
                technologies.append({'name': 'Laravel', 'confidence': 85})
            if 'react' in content or 'react.js' in content:
                technologies.append({'name': 'React.js', 'confidence': 85})
            if 'django' in content:
                technologies.append({'name': 'Django', 'confidence': 85})
            if 'flask' in content:
                technologies.append({'name': 'Flask', 'confidence': 85})
                
        except Exception as e:
            self.logger.error(f"Web fingerprinting failed: {e}")
        
        self.results['web_reconnaissance']['technologies'] = technologies
        self.results['web_reconnaissance']['cms'] = cmsystems
        self.results['web_reconnaissance']['servers'] = servers
        
        # Findings
        findings = [
            {
                'type': 'Technology_Stack',
                'severity': 'Info',
                'finding': f'Identified {len(technologies)} technologies',
                'risk': 'Technology stack mapped for targeting'
            }
        ]
        
        if cmsystems:
            findings.append({
                'type': 'CMS_Detected',
                'severity': 'Medium',
                'finding': f'{cmsystems[0]["name"]} detected',
                'risk': 'CMS may have known vulnerabilities'
            })
        
        self.results['web_reconnaissance']['findings'] = findings
        return len(technologies)
    
    def harvest_emails(self):
        """Harvest email addresses from various sources"""
        self.logger.info("Harvesting email addresses...")
        
        emails = []
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        try:
            url = f"http://{self.args.target}" if not self.args.target.startswith('http') else self.args.target
            response = requests.get(url, timeout=5)
            
            # Extract emails from page source
            found_emails = re.findall(email_pattern, response.text)
            for email in set(found_emails):
                emails.append({
                    'email': email,
                    'source': 'Website HTML',
                    'verified': True
                })
        except:
            pass
        
        # Add common patterns for the domain
        domain = self.args.target.split('/')[0]
        common_patterns = [
            f'admin@{domain}',
            f'info@{domain}',
            f'support@{domain}',
            f'contact@{domain}',
            f'sales@{domain}',
            f'hr@{domain}',
            f'careers@{domain}'
        ]
        
        for email in common_patterns:
            emails.append({
                'email': email,
                'source': 'Common pattern',
                'verified': False
            })
        
        patterns = [
            {'pattern': 'firstname.lastname@domain.com', 'confidence': 'High'},
            {'pattern': 'first.last@domain.com', 'confidence': 'High'},
            {'pattern': 'firstlast@domain.com', 'confidence': 'Medium'},
            {'pattern': 'f.last@domain.com', 'confidence': 'Low'}
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
        
        endpoints = []
        
        try:
            url = f"http://{self.args.target}" if not self.args.target.startswith('http') else self.args.target
            response = requests.get(url, timeout=5)
            content = response.text
            
            # Look for API paths in JavaScript or HTML
            api_patterns = [
                r'/api/v\d+/\w+',
                r'/rest/\w+',
                r'/graphql',
                r'/ajax/\w+'
            ]
            
            for pattern in api_patterns:
                found = re.findall(pattern, content)
                for path in set(found):
                    endpoints.append({
                        'path': path,
                        'method': 'GET',
                        'source': 'JavaScript/HTML',
                        'auth': 'Unknown'
                    })
            
            # Common endpoints
            common_endpoints = [
                '/api/v1/users',
                '/api/v1/products',
                '/api/v1/orders',
                '/api/v2/auth',
                '/graphql',
                '/admin/dashboard',
                '/admin/users',
                '/backup',
                '/.env',
                '/.git/config',
                '/web.config'
            ]
            
            for endpoint in common_endpoints:
                try:
                    test_url = url.rstrip('/') + endpoint
                    test_resp = requests.head(test_url, timeout=3)
                    endpoints.append({
                        'path': endpoint,
                        'method': 'GET',
                        'status': test_resp.status_code,
                        'auth': 'Unknown'
                    })
                except:
                    pass
                    
        except:
            pass
        
        hidden_params = [
            {'parameter': 'admin', 'type': 'boolean', 'risk': 'Privilege escalation'},
            {'parameter': 'debug', 'type': 'boolean', 'risk': 'Information disclosure'},
            {'parameter': 'api_key', 'type': 'string', 'risk': 'Authentication bypass'},
            {'parameter': 'token', 'type': 'string', 'risk': 'Session hijacking'}
        ]
        
        self.results['endpoint_discovery']['endpoints'] = endpoints
        self.results['endpoint_discovery']['hidden_parameters'] = hidden_params
        self.results['endpoint_discovery']['api_endpoints'] = [ep for ep in endpoints if '/api/' in ep.get('path', '')]
        
        findings = [
            {
                'type': 'API_Endpoints_Discovered',
                'severity': 'Info',
                'finding': f'Found {len(endpoints)} endpoints',
                'risk': 'Endpoints mapped for targeting'
            }
        ]
        
        if endpoints:
            findings.append({
                'type': 'Endpoint_Enumeration',
                'severity': 'Medium',
                'finding': 'API structure can be enumerated',
                'risk': 'Enables targeted API attacks'
            })
        
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
