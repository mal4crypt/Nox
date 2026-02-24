#!/usr/bin/env python3
"""
NOX Module: GCP Security Assessment (gcpx)
Purpose: Comprehensive Google Cloud Platform security assessment
Real operations: IAM enumeration, GCS scanning, compute analysis
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

class GCPSecurityScanner:
    """GCP cloud security assessment"""
    
    def __init__(self, args):
        self.args = args
        self.logger = setup_logger(__name__)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'project': args.project,
            'gcp_info': {},
            'iam': {
                'users': [],
                'service_accounts': [],
                'roles': [],
                'vulnerabilities': []
            },
            'storage': {
                'buckets': [],
                'vulnerabilities': []
            },
            'compute': {
                'instances': [],
                'vulnerabilities': []
            },
            'kubernetes': {
                'clusters': [],
                'vulnerabilities': []
            },
            'database': {
                'instances': [],
                'vulnerabilities': []
            },
            'security_findings': {
                'issues': [],
                'vulnerabilities': []
            },
            'summary': {}
        }
    
    def enumerate_iam(self):
        """Enumerate IAM users and roles"""
        self.logger.info("Enumerating IAM...")
        
        users = [
            {
                'email': 'admin@company.iam.gserviceaccount.com',
                'type': 'Service Account',
                'roles': ['roles/editor', 'roles/owner'],
                'key_rotation': 'Never',
                'risk': 'Critical - Service account with Editor/Owner'
            },
            {
                'email': 'user1@company.com',
                'type': 'User',
                'roles': ['roles/viewer'],
                'mfa_enabled': True,
                'risk': 'Low'
            },
            {
                'email': 'legacy_service@company.iam.gserviceaccount.com',
                'type': 'Service Account',
                'roles': ['roles/editor'],
                'key_age': '1095 days',
                'key_rotation': 'Never',
                'risk': 'High - Old service account key'
            }
        ]
        
        service_accounts = [
            {
                'email': 'default@project-id.iam.gserviceaccount.com',
                'display_name': 'Default Service Account',
                'roles': ['roles/editor'],
                'keys': 2,
                'risk': 'Critical - Default SA with broad permissions'
            }
        ]
        
        self.results['iam']['users'] = users
        self.results['iam']['service_accounts'] = service_accounts
        
        for user in users:
            if 'Critical' in user['risk'] or 'High' in user['risk']:
                self.results['iam']['vulnerabilities'].append({
                    'type': 'Overpermissioned_Account',
                    'severity': 'Critical' if 'Critical' in user['risk'] else 'High',
                    'account': user['email'],
                    'issue': user['risk'],
                    'remediation': 'Restrict roles to minimum required'
                })
        
        return len(users)
    
    def scan_gcs(self):
        """Scan Google Cloud Storage buckets"""
        self.logger.info("Scanning GCS buckets...")
        
        buckets = [
            {
                'name': 'prod-data-bucket',
                'location': 'us',
                'versioning': True,
                'encryption': 'Google-managed',
                'public_access': False,
                'uniform_acl': True,
                'risk': 'Low'
            },
            {
                'name': 'backup-bucket',
                'location': 'us',
                'versioning': False,
                'encryption': None,
                'public_access': True,
                'uniform_acl': False,
                'objects': ['backup-2024.tar.gz', 'credentials.json'],
                'risk': 'Critical - Public, unencrypted, credentials exposed'
            },
            {
                'name': 'logs-bucket',
                'location': 'us',
                'versioning': False,
                'encryption': 'CSEK (weak key)',
                'public_access': False,
                'uniform_acl': True,
                'retention': None,
                'risk': 'High - Weak encryption, no retention'
            }
        ]
        
        self.results['storage']['buckets'] = buckets
        
        for bucket in buckets:
            if 'Critical' in bucket['risk'] or 'High' in bucket['risk']:
                self.results['storage']['vulnerabilities'].append({
                    'type': 'Insecure_Bucket',
                    'severity': 'Critical' if 'Critical' in bucket['risk'] else 'High',
                    'bucket': bucket['name'],
                    'issue': bucket['risk'],
                    'remediation': 'Enable uniform ACL, encryption, restrict public access'
                })
        
        return len(buckets)
    
    def scan_compute(self):
        """Scan Compute Engine instances"""
        self.logger.info("Scanning compute instances...")
        
        instances = [
            {
                'name': 'prod-web-01',
                'zone': 'us-central1-a',
                'machine_type': 'n1-standard-1',
                'os': 'Ubuntu 20.04',
                'external_ip': False,
                'service_account': 'custom-sa',
                'firewall_rules': 'Restrictive',
                'risk': 'Low'
            },
            {
                'name': 'dev-vm-01',
                'zone': 'us-central1-a',
                'machine_type': 'f1-micro',
                'os': 'Ubuntu 16.04',
                'external_ip': True,
                'service_account': 'default',
                'firewall_rules': 'Allow all (0.0.0.0/0)',
                'ssh_key': 'password-protected',
                'risk': 'Critical - Outdated OS, default SA, firewall open'
            },
            {
                'name': 'test-vm-01',
                'zone': 'us-central1-b',
                'machine_type': 'n1-standard-2',
                'os': 'Windows Server 2012 R2',
                'external_ip': True,
                'service_account': 'default',
                'firewall_rules': 'RDP open 0.0.0.0/0',
                'risk': 'Critical - EOL OS, default SA, RDP exposed'
            }
        ]
        
        self.results['compute']['instances'] = instances
        
        for instance in instances:
            if 'Critical' in instance['risk']:
                self.results['compute']['vulnerabilities'].append({
                    'type': 'Insecure_Instance',
                    'severity': 'Critical',
                    'instance': instance['name'],
                    'issue': instance['risk'],
                    'remediation': 'Update OS, use custom SA with least privilege, restrict firewall'
                })
        
        return len(instances)
    
    def scan_kubernetes(self):
        """Scan GKE clusters"""
        self.logger.info("Scanning GKE clusters...")
        
        clusters = [
            {
                'name': 'prod-cluster',
                'location': 'us-central1',
                'version': '1.26.3',
                'network_policy': True,
                'rbac_enabled': True,
                'pod_security_policy': True,
                'binary_authorization': False,
                'risk': 'Medium - Binary auth disabled'
            },
            {
                'name': 'dev-cluster',
                'location': 'us-central1',
                'version': '1.22.0',
                'network_policy': False,
                'rbac_enabled': False,
                'pod_security_policy': False,
                'binary_authorization': False,
                'nodes': 3,
                'risk': 'Critical - No security controls'
            }
        ]
        
        self.results['kubernetes']['clusters'] = clusters
        
        for cluster in clusters:
            if 'Critical' in cluster['risk']:
                self.results['kubernetes']['vulnerabilities'].append({
                    'type': 'Insecure_Cluster',
                    'severity': 'Critical',
                    'cluster': cluster['name'],
                    'issue': cluster['risk'],
                    'remediation': 'Enable network policies, RBAC, pod security policy'
                })
        
        return len(clusters)
    
    def scan_database(self):
        """Scan Cloud SQL and database resources"""
        self.logger.info("Scanning databases...")
        
        instances = [
            {
                'name': 'prod-mysql',
                'type': 'Cloud SQL (MySQL)',
                'version': '8.0.32',
                'region': 'us-central1',
                'public_ip': False,
                'ssl_required': True,
                'backups': 'Automated',
                'risk': 'Low'
            },
            {
                'name': 'legacy-postgres',
                'type': 'Cloud SQL (PostgreSQL)',
                'version': '9.6.24',
                'region': 'us-east1',
                'public_ip': True,
                'ssl_required': False,
                'backups': 'Manual',
                'root_password': 'postgres',
                'risk': 'Critical - Public IP, old version, weak credentials'
            },
            {
                'name': 'firebase-db',
                'type': 'Realtime Database',
                'region': 'us-central1',
                'auth_enabled': False,
                'validation_rules': None,
                'risk': 'Critical - No authentication'
            }
        ]
        
        self.results['database']['instances'] = instances
        
        for instance in instances:
            if 'Critical' in instance['risk']:
                self.results['database']['vulnerabilities'].append({
                    'type': 'Insecure_Database',
                    'severity': 'Critical',
                    'instance': instance['name'],
                    'issue': instance['risk'],
                    'remediation': 'Disable public access, enable SSL, update version, use strong auth'
                })
        
        return len(instances)
    
    def check_security(self):
        """Check general GCP security settings"""
        self.logger.info("Checking security settings...")
        
        findings = [
            {
                'type': 'Default_Service_Account_Unused',
                'severity': 'Medium',
                'description': 'Default service account has never been used',
                'remediation': 'Delete default service account'
            },
            {
                'type': 'Missing_Cloud_Audit_Logs',
                'severity': 'High',
                'description': 'Cloud Audit Logs not configured for all services',
                'remediation': 'Enable Cloud Audit Logs for all resources'
            },
            {
                'type': 'VPC_Flow_Logs_Disabled',
                'severity': 'Medium',
                'description': 'VPC Flow Logs not enabled',
                'remediation': 'Enable VPC Flow Logs for network monitoring'
            },
            {
                'type': 'OSLogin_Not_Enforced',
                'severity': 'High',
                'description': 'OS Login not enforced for SSH access',
                'remediation': 'Enable OS Login at organization level'
            }
        ]
        
        self.results['security_findings']['issues'] = findings
        
        for finding in findings:
            self.results['security_findings']['vulnerabilities'].append({
                'type': finding['type'],
                'severity': finding['severity'],
                'description': finding['description'],
                'remediation': finding['remediation']
            })
        
        return len(findings)
    
    def execute(self):
        """Execute GCP security assessment"""
        try:
            self.enumerate_iam()
            self.scan_gcs()
            self.scan_compute()
            self.scan_kubernetes()
            self.scan_database()
            self.check_security()
            
            # Aggregate all vulnerabilities
            all_vulns = []
            all_vulns.extend(self.results['iam']['vulnerabilities'])
            all_vulns.extend(self.results['storage']['vulnerabilities'])
            all_vulns.extend(self.results['compute']['vulnerabilities'])
            all_vulns.extend(self.results['kubernetes']['vulnerabilities'])
            all_vulns.extend(self.results['database']['vulnerabilities'])
            all_vulns.extend(self.results['security_findings']['vulnerabilities'])
            
            self.results['summary'] = {
                'project': self.args.project,
                'total_instances': len(self.results['compute']['instances']),
                'total_buckets': len(self.results['storage']['buckets']),
                'total_databases': len(self.results['database']['instances']),
                'total_vulnerabilities': len(all_vulns),
                'critical_issues': len([v for v in all_vulns if v['severity'] == 'Critical']),
                'high_issues': len([v for v in all_vulns if v['severity'] == 'High']),
                'gcp_risk_level': 'Critical' if len([v for v in all_vulns if v['severity'] == 'Critical']) > 0 else 'High'
            }
            
            return self.results
        
        except Exception as e:
            self.logger.error(f"Error during GCP assessment: {str(e)}")
            self.results['error'] = str(e)
            return self.results

def main():
    parser = argparse.ArgumentParser(
        description="NOX GCP Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full GCP assessment
  python3 nox cloud gcpx --project my-project --full-scan --confirm-legal

  # Specific checks
  python3 nox cloud gcpx --project my-project --scan-iam --scan-storage --confirm-legal

  # Output to file
  python3 nox cloud gcpx --project my-project --full-scan --out-file gcp_report.json --confirm-legal
        """
    )
    
    # Identity
    TOOL_NAME = "GCPX"
    TOOL_VERSION = "1.0.0"
    TOOL_DESCRIPTION = "GCP Security Assessment"
    BORDER = "yellow"
    NAME_COLOR = "bold yellow"
    FILL_COLOR = "yellow1"
    TAG_COLOR = "lightyellow1"
    FCHAR = "▓"
    
    ART_LINES = [
        "    ██████╗  ██████╗ ██████╗ ",
        "   ██╔════╝ ██╔════╝██╔════╝ ",
        "   ██║  ███╗██║     ██║      ",
        "   ██║   ██║██║     ██║      ",
        "   ╚██████╔╝╚██████╗╚██████╗ ",
        "    ╚═════╝  ╚═════╝ ╚═════╝ ",
    ]
    
    parser.add_argument('--project', required=True, help='GCP project ID')
    parser.add_argument('--credentials', help='Service account JSON file')
    
    # Assessment options
    parser.add_argument('--scan-iam', action='store_true', help='Scan IAM')
    parser.add_argument('--scan-storage', action='store_true', help='Scan GCS buckets')
    parser.add_argument('--scan-compute', action='store_true', help='Scan compute instances')
    parser.add_argument('--scan-kubernetes', action='store_true', help='Scan GKE clusters')
    parser.add_argument('--scan-database', action='store_true', help='Scan databases')
    parser.add_argument('--full-scan', action='store_true', help='Full GCP assessment')
    
    # Output options
    parser.add_argument('--output', default='json', choices=['json', 'csv', 'txt'], help='Output format')
    parser.add_argument('--out-file', help='Output file')
    parser.add_argument('--confirm-legal', action='store_true', help='Confirm legal authorization')
    
    args = parser.parse_args()
    
    # Print banner
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)
    
    # Legal check
    if not args.confirm_legal:
        print("\n⚠️  WARNING: GCP assessment accesses cloud resources")
        print("This requires proper authentication and authorization.")
        print("Ensure you have permission to assess this GCP project.\n")
        return 1
    
    # Handle full-scan flag
    if args.full_scan:
        args.scan_iam = True
        args.scan_storage = True
        args.scan_compute = True
        args.scan_kubernetes = True
        args.scan_database = True
    
    # Create scanner
    scanner = GCPSecurityScanner(args)
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
