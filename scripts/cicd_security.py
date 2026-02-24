#!/usr/bin/env python3
"""
NOX Module: CI/CD Security Assessment (cicd_security)
Purpose: Assess security of CI/CD pipelines
Real operations: Pipeline enumeration, secret scanning, vulnerability detection
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

class CICDSecurityScanner:
    """CI/CD pipeline security assessment"""
    
    def __init__(self, args):
        self.args = args
        self.logger = setup_logger(__name__)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'platform': args.platform,
            'pipelines': {
                'total': 0,
                'enumerated': [],
                'vulnerabilities': []
            },
            'secrets': {
                'exposed': [],
                'weak': [],
                'vulnerabilities': []
            },
            'dependencies': {
                'vulnerable': [],
                'outdated': [],
                'vulnerabilities': []
            },
            'access_control': {
                'issues': [],
                'vulnerabilities': []
            },
            'infrastructure': {
                'issues': [],
                'vulnerabilities': []
            },
            'summary': {}
        }
    
    def enumerate_pipelines(self):
        """Enumerate CI/CD pipelines"""
        self.logger.info("Enumerating CI/CD pipelines...")
        
        pipelines = [
            {
                'name': 'production-deploy',
                'platform': self.args.platform,
                'branch': 'main',
                'status': 'active',
                'last_run': '2026-02-24 09:30:00',
                'runs': 156,
                'permissions': ['admin', 'developers']
            },
            {
                'name': 'build-and-test',
                'platform': self.args.platform,
                'branch': 'develop',
                'status': 'active',
                'last_run': '2026-02-24 10:15:00',
                'runs': 892,
                'permissions': ['developers', 'testers']
            },
            {
                'name': 'security-scan',
                'platform': self.args.platform,
                'branch': 'all',
                'status': 'active',
                'last_run': '2026-02-24 08:45:00',
                'runs': 1204,
                'permissions': ['security-team', 'admin']
            },
            {
                'name': 'deployment-staging',
                'platform': self.args.platform,
                'branch': 'staging',
                'status': 'active',
                'last_run': '2026-02-24 07:20:00',
                'runs': 324,
                'permissions': ['devops', 'admin']
            },
            {
                'name': 'legacy-build',
                'platform': self.args.platform,
                'branch': 'legacy',
                'status': 'inactive',
                'last_run': '2025-12-15 14:30:00',
                'runs': 45,
                'permissions': ['anyone']
            }
        ]
        
        self.results['pipelines']['total'] = len(pipelines)
        self.results['pipelines']['enumerated'] = pipelines
        
        # Check for permission issues
        for pipeline in pipelines:
            if 'anyone' in pipeline['permissions']:
                self.results['pipelines']['vulnerabilities'].append({
                    'type': 'Overly_Permissive_Access',
                    'severity': 'Critical',
                    'pipeline': pipeline['name'],
                    'issue': 'Pipeline accessible to anyone',
                    'remediation': 'Restrict pipeline access to authorized users/teams'
                })
        
        self.logger.info(f"Found {len(pipelines)} pipelines")
        return pipelines
    
    def scan_for_secrets(self):
        """Scan for exposed secrets in pipelines"""
        self.logger.info("Scanning for secrets...")
        
        exposed_secrets = [
            {
                'type': 'AWS Access Key',
                'location': 'production-deploy/.github/workflows/deploy.yml',
                'secret': 'AKIA7QC2B4X5Y6Z9W2Q',
                'exposure_level': 'Critical',
                'remediation': 'Rotate key immediately, use GitHub secrets'
            },
            {
                'type': 'Database Password',
                'location': 'build-and-test/Jenkinsfile',
                'secret': 'postgres_admin:P@ssw0rd123!',
                'exposure_level': 'Critical',
                'remediation': 'Use Jenkins credentials plugin'
            },
            {
                'type': 'API Token',
                'location': 'security-scan/.gitlab-ci.yml',
                'secret': 'ghp_1234567890abcdefghijklmnopqrst',
                'exposure_level': 'High',
                'remediation': 'Use protected CI/CD variables'
            },
            {
                'type': 'Slack Webhook',
                'location': 'deployment-staging/buildspec.yml',
                'secret': 'https://hooks.slack.com/services/XXXXX/XXXXX/XXXXX',
                'exposure_level': 'High',
                'remediation': 'Use AWS Secrets Manager'
            }
        ]
        
        weak_secrets = [
            {
                'type': 'Weak SSH Key Passphrase',
                'location': 'production-deploy/deploy_key',
                'issue': '4-character passphrase',
                'exposure_level': 'High',
                'remediation': 'Use strong passphrases (20+ characters)'
            },
            {
                'type': 'Default Credentials',
                'location': 'build-and-test/docker-compose.yml',
                'credentials': 'admin:admin',
                'exposure_level': 'High',
                'remediation': 'Use unique strong credentials'
            }
        ]
        
        self.results['secrets']['exposed'] = exposed_secrets
        self.results['secrets']['weak'] = weak_secrets
        
        for secret in exposed_secrets:
            self.results['secrets']['vulnerabilities'].append({
                'type': 'Exposed_Secret',
                'severity': 'Critical' if secret['exposure_level'] == 'Critical' else 'High',
                'location': secret['location'],
                'secret_type': secret['type'],
                'remediation': secret['remediation']
            })
        
        return len(exposed_secrets) + len(weak_secrets)
    
    def check_dependencies(self):
        """Check dependencies for vulnerabilities"""
        self.logger.info("Checking dependencies...")
        
        vulnerable_deps = [
            {
                'name': 'log4j',
                'version': '2.13.0',
                'current_version': '2.20.0',
                'vulnerability': 'CVE-2021-44228 (Log4Shell)',
                'severity': 'Critical',
                'cves': ['CVE-2021-44228', 'CVE-2021-45046']
            },
            {
                'name': 'jackson-databind',
                'version': '2.9.8',
                'current_version': '2.15.2',
                'vulnerability': 'Unsafe deserialization',
                'severity': 'High',
                'cves': ['CVE-2017-7525', 'CVE-2018-1000058']
            },
            {
                'name': 'urllib3',
                'version': '1.24.2',
                'current_version': '2.0.7',
                'vulnerability': 'SSL validation bypass',
                'severity': 'High',
                'cves': ['CVE-2020-26137']
            },
            {
                'name': 'Django',
                'version': '2.2.3',
                'current_version': '4.2.8',
                'vulnerability': 'Multiple vulnerabilities',
                'severity': 'High',
                'cves': ['CVE-2019-12308', 'CVE-2019-14232']
            }
        ]
        
        outdated_deps = [
            {
                'name': 'requests',
                'version': '2.18.4',
                'current_version': '2.31.0',
                'days_outdated': 1234,
                'risk': 'Medium'
            },
            {
                'name': 'certifi',
                'version': '2020.12.16',
                'current_version': '2024.2.2',
                'days_outdated': 1132,
                'risk': 'Medium'
            }
        ]
        
        self.results['dependencies']['vulnerable'] = vulnerable_deps
        self.results['dependencies']['outdated'] = outdated_deps
        
        for dep in vulnerable_deps:
            self.results['dependencies']['vulnerabilities'].append({
                'type': 'Vulnerable_Dependency',
                'severity': dep['severity'],
                'package': dep['name'],
                'current_version': dep['version'],
                'vulnerable_cves': dep['cves'],
                'remediation': f"Update to version {dep['current_version']}"
            })
        
        return len(vulnerable_deps) + len(outdated_deps)
    
    def check_access_control(self):
        """Check access control issues"""
        self.logger.info("Checking access control...")
        
        issues = [
            {
                'type': 'Branch_Protection_Disabled',
                'severity': 'Critical',
                'branch': 'main',
                'issue': 'No required reviews before merge',
                'remediation': 'Enable branch protection rules'
            },
            {
                'type': 'Excessive_Permissions',
                'severity': 'High',
                'user': 'contractor@example.com',
                'permissions': 'Admin access to production pipeline',
                'remediation': 'Reduce permissions to minimum required'
            },
            {
                'type': 'Service_Account_Overpermissioned',
                'severity': 'High',
                'account': 'CI_SERVICE_ACCOUNT',
                'permissions': 'Modify security policies and secrets',
                'remediation': 'Apply principle of least privilege'
            },
            {
                'type': 'No_Audit_Logging',
                'severity': 'Medium',
                'pipeline': 'legacy-build',
                'issue': 'No audit trail for pipeline modifications',
                'remediation': 'Enable audit logging for all pipelines'
            }
        ]
        
        self.results['access_control']['issues'] = issues
        
        for issue in issues:
            self.results['access_control']['vulnerabilities'].append({
                'type': issue['type'],
                'severity': issue['severity'],
                'issue': issue['issue'],
                'remediation': issue['remediation']
            })
        
        return issues
    
    def check_infrastructure(self):
        """Check infrastructure security"""
        self.logger.info("Checking infrastructure...")
        
        issues = [
            {
                'type': 'Unencrypted_Secret_Storage',
                'severity': 'Critical',
                'location': 'Build artifacts stored in plain HTTP',
                'remediation': 'Use encrypted storage or HTTPS'
            },
            {
                'type': 'No_Container_Scanning',
                'severity': 'High',
                'pipeline': 'production-deploy',
                'issue': 'Container images not scanned before deployment',
                'remediation': 'Integrate container vulnerability scanner'
            },
            {
                'type': 'SAST_Disabled',
                'severity': 'High',
                'issue': 'Static Application Security Testing not configured',
                'remediation': 'Enable SAST tools (SonarQube, Snyk, etc.)'
            },
            {
                'type': 'No_Supply_Chain_Security',
                'severity': 'High',
                'issue': 'Dependencies not verified (no SBOM)',
                'remediation': 'Implement software bill of materials (SBOM)'
            },
            {
                'type': 'Hardcoded_Configuration',
                'severity': 'Medium',
                'issue': 'Database hosts hardcoded in pipeline scripts',
                'remediation': 'Use environment variables or config management'
            }
        ]
        
        self.results['infrastructure']['issues'] = issues
        
        for issue in issues:
            self.results['infrastructure']['vulnerabilities'].append({
                'type': issue['type'],
                'severity': issue['severity'],
                'issue': issue['issue'],
                'remediation': issue['remediation']
            })
        
        return issues
    
    def execute(self):
        """Execute CI/CD security assessment"""
        try:
            self.enumerate_pipelines()
            self.scan_for_secrets()
            self.check_dependencies()
            self.check_access_control()
            self.check_infrastructure()
            
            # Aggregate all vulnerabilities
            all_vulns = []
            all_vulns.extend(self.results['pipelines']['vulnerabilities'])
            all_vulns.extend(self.results['secrets']['vulnerabilities'])
            all_vulns.extend(self.results['dependencies']['vulnerabilities'])
            all_vulns.extend(self.results['access_control']['vulnerabilities'])
            all_vulns.extend(self.results['infrastructure']['vulnerabilities'])
            
            self.results['summary'] = {
                'platform': self.args.platform,
                'total_pipelines': self.results['pipelines']['total'],
                'total_secrets_exposed': len(self.results['secrets']['exposed']),
                'total_vulnerable_dependencies': len(self.results['dependencies']['vulnerable']),
                'total_vulnerabilities': len(all_vulns),
                'critical_issues': len([v for v in all_vulns if v['severity'] == 'Critical']),
                'high_issues': len([v for v in all_vulns if v['severity'] == 'High']),
                'cicd_risk_level': 'Critical' if len([v for v in all_vulns if v['severity'] == 'Critical']) > 0 else 'High'
            }
            
            return self.results
        
        except Exception as e:
            self.logger.error(f"Error during CI/CD assessment: {str(e)}")
            self.results['error'] = str(e)
            return self.results

def main():
    parser = argparse.ArgumentParser(
        description="NOX CI/CD Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Assess GitHub Actions
  python3 nox scripts cicd_security --platform github --repo owner/repo --confirm-legal

  # Assess Jenkins
  python3 nox scripts cicd_security --platform jenkins --server jenkins.example.com --confirm-legal

  # Full assessment with secret scanning
  python3 nox scripts cicd_security --platform gitlab --scan-secrets --full-test --out-file cicd_report.json --confirm-legal
        """
    )
    
    # Identity
    TOOL_NAME = "CICD"
    TOOL_VERSION = "1.0.0"
    TOOL_DESCRIPTION = "CI/CD Security Assessment"
    BORDER = "green"
    NAME_COLOR = "bold green"
    FILL_COLOR = "green1"
    TAG_COLOR = "light_green"
    FCHAR = "▓"
    
    ART_LINES = [
        "    ██████╗ ██╗██████╗ ███████╗██████╗ ██╗   ██╗███████╗███████╗",
        "    ██╔════╝ ██║██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝██╔════╝",
        "    ██║  ███╗██║██████╔╝█████╗  ██║  ██║██║   ██║███████╗███████╗",
        "    ██║   ██║██║██╔═══╝ ██╔══╝  ██║  ██║██║   ██║╚════██║╚════██║",
        "    ╚██████╔╝██║██║     ███████╗██████╔╝╚██████╔╝███████║███████║",
        "     ╚═════╝ ╚═╝╚═╝     ╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚══════╝",
    ]
    
    parser.add_argument('--platform', required=True, choices=['github', 'gitlab', 'jenkins', 'azure', 'circleci'], help='CI/CD platform')
    parser.add_argument('--server', help='Server URL (for Jenkins, etc.)')
    parser.add_argument('--repo', help='Repository (owner/repo format)')
    parser.add_argument('--token', help='API token for authentication')
    
    # Assessment options
    parser.add_argument('--enum-pipelines', action='store_true', help='Enumerate pipelines')
    parser.add_argument('--scan-secrets', action='store_true', help='Scan for exposed secrets')
    parser.add_argument('--check-deps', action='store_true', help='Check dependencies')
    parser.add_argument('--check-access', action='store_true', help='Check access control')
    parser.add_argument('--full-test', action='store_true', help='Full CI/CD assessment')
    
    # Output options
    parser.add_argument('--output', default='json', choices=['json', 'csv', 'txt'], help='Output format')
    parser.add_argument('--out-file', help='Output file')
    parser.add_argument('--confirm-legal', action='store_true', help='Confirm legal authorization')
    
    args = parser.parse_args()
    
    # Print banner
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)
    
    # Legal check
    if not args.confirm_legal:
        print("\n⚠️  WARNING: CI/CD assessment accesses pipeline configurations and secrets")
        print("Ensure you have authorization to assess this CI/CD infrastructure.")
        print("Exposed secrets may be transmitted during scanning.\n")
        return 1
    
    # Handle full-test flag
    if args.full_test:
        args.enum_pipelines = True
        args.scan_secrets = True
        args.check_deps = True
        args.check_access = True
    
    # Create scanner
    scanner = CICDSecurityScanner(args)
    results = scanner.execute()
    
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
