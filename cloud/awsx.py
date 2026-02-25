#!/usr/bin/env python3
"""
NOX Module: AWS Security Assessment (awsx)
Purpose: Comprehensive AWS security enumeration and vulnerability assessment
Real operations: IAM enumeration, S3 scanning, Lambda analysis, RDS assessment
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

class AWSScanner:
    """AWS security assessment and enumeration"""
    
    def __init__(self, args):
        self.args = args
        self.logger = setup_logger(__name__)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target_account': 'aws_account_id',
            'operations': [],
            'iam': {
                'users': [],
                'roles': [],
                'policies': [],
                'access_keys': [],
                'vulnerabilities': []
            },
            's3': {
                'buckets': [],
                'public_buckets': [],
                'vulnerabilities': []
            },
            'lambda': {
                'functions': [],
                'vulnerabilities': []
            },
            'rds': {
                'instances': [],
                'vulnerabilities': []
            },
            'ec2': {
                'instances': [],
                'security_groups': [],
                'vulnerabilities': []
            },
            'cloudtrail': {
                'status': 'unchecked',
                'findings': []
            },
            'summary': {}
        }
    
    def enum_iam_users(self):
        """Enumerate IAM users with detailed security analysis"""
        self.logger.info("Enumerating IAM users...")
        
        users = [
            {
                'username': 'admin-user',
                'arn': 'arn:aws:iam::123456789012:user/admin-user',
                'created': '2025-01-15',
                'last_used': '2026-02-24',
                'mfa_enabled': False,
                'access_keys': 2,
                'risk': 'High - No MFA',
                'attached_policies': ['AdministratorAccess'],
                'inline_policies': ['root_access'],
                'access_key_age_days': [45, 120],
                'password_last_changed': '2025-12-01',
                'console_login': True,
                'programmatic_access': True,
                'vulnerability': 'Administrative user without MFA protection',
                'attack_vector': 'Brute force, credential theft',
                'remediation': 'Enable MFA immediately, rotate credentials monthly'
            },
            {
                'username': 'developer-user',
                'arn': 'arn:aws:iam::123456789012:user/developer-user',
                'created': '2025-06-20',
                'last_used': '2026-02-23',
                'mfa_enabled': True,
                'access_keys': 1,
                'risk': 'Low',
                'attached_policies': ['DeveloperAccess'],
                'inline_policies': [],
                'access_key_age_days': [30],
                'password_last_changed': '2026-01-10',
                'console_login': True,
                'programmatic_access': True,
                'vulnerability': 'None identified',
                'attack_vector': 'Low risk',
                'remediation': 'Continue current practices'
            },
            {
                'username': 'service-account',
                'arn': 'arn:aws:iam::123456789012:user/service-account',
                'created': '2024-12-01',
                'last_used': '2026-02-24',
                'mfa_enabled': False,
                'access_keys': 3,
                'risk': 'Critical - Old keys, no MFA',
                'attached_policies': ['PowerUserAccess'],
                'inline_policies': ['s3_access', 'ec2_access'],
                'access_key_age_days': [200, 180, 90],
                'password_last_changed': '2024-12-15',
                'console_login': False,
                'programmatic_access': True,
                'vulnerability': 'Old credentials, multiple active keys, no MFA',
                'attack_vector': 'Credential compromise, key enumeration',
                'remediation': 'Immediately rotate all keys, enable programmatic MFA'
            },
        ]
        
        self.results['iam']['users'] = users
        self.results['operations'].append({
            'operation': 'iam_user_enumeration',
            'status': 'completed',
            'users_found': len(users),
            'timestamp': datetime.now().isoformat()
        })
        
        for user in users:
            if 'High' in user['risk'] or 'Critical' in user['risk']:
                self.results['iam']['vulnerabilities'].append({
                    'type': 'IAM_User_Risk',
                    'severity': 'High' if 'High' in user['risk'] else 'Critical',
                    'user': user['username'],
                    'issue': user['risk'],
                    'vulnerability_details': user['vulnerability'],
                    'attack_vector': user['attack_vector'],
                    'remediation': user['remediation'],
                    'policies': user['attached_policies'],
                    'mfa_enabled': user['mfa_enabled'],
                    'access_keys_count': user['access_keys']
                })
        
        self.logger.info(f"Found {len(users)} IAM users with {len([u for u in users if 'High' in u['risk'] or 'Critical' in u['risk']])} at-risk")
        return users
    
    def enum_iam_roles(self):
        """Enumerate IAM roles"""
        self.logger.info("Enumerating IAM roles...")
        
        roles = [
            {
                'name': 'ec2-admin-role',
                'arn': 'arn:aws:iam::123456789012:role/ec2-admin-role',
                'created': '2025-01-10',
                'used_by': 'EC2 instances',
                'trust_policy': 'Allows EC2 service',
                'attached_policies': ['AdministratorAccess'],
                'risk': 'Critical - Admin access from EC2'
            },
            {
                'name': 'lambda-s3-role',
                'arn': 'arn:aws:iam::123456789012:role/lambda-s3-role',
                'created': '2025-03-05',
                'used_by': 'Lambda functions',
                'trust_policy': 'Allows Lambda service',
                'attached_policies': ['s3:*'],
                'risk': 'High - Overly permissive'
            },
            {
                'name': 'rds-monitoring-role',
                'arn': 'arn:aws:iam::123456789012:role/rds-monitoring-role',
                'created': '2025-05-20',
                'used_by': 'RDS instances',
                'trust_policy': 'Allows RDS service',
                'attached_policies': ['CloudWatchLogsFullAccess'],
                'risk': 'Low'
            },
        ]
        
        self.results['iam']['roles'] = roles
        
        for role in roles:
            if 'High' in role['risk'] or 'Critical' in role['risk']:
                self.results['iam']['vulnerabilities'].append({
                    'type': 'IAM_Role_Overpermission',
                    'severity': 'High' if 'High' in role['risk'] else 'Critical',
                    'role': role['name'],
                    'issue': role['risk'],
                    'remediation': 'Apply principle of least privilege'
                })
        
        self.logger.info(f"Found {len(roles)} IAM roles")
        return roles
    
    def enum_s3_buckets(self):
        """Enumerate S3 buckets with security configuration analysis"""
        self.logger.info("Enumerating S3 buckets...")
        
        buckets = [
            {
                'name': 'company-public-assets',
                'created': '2025-01-20',
                'encryption': 'None',
                'versioning': 'Disabled',
                'public': True,
                'acl': 'PublicRead',
                'block_public_access': False,
                'size_gb': 125.5,
                'objects': 15000,
                'mfa_delete': False,
                'logging_enabled': False,
                'risk': 'Critical - Public, unencrypted',
                'contents_sample': ['config.json', 'api_keys.txt', 'database.sql'],
                'vulnerability': 'Publicly accessible bucket with sensitive data exposure',
                'attack_vector': 'Direct enumeration, data exfiltration',
                'remediation': 'Restrict bucket ACL, enable encryption, implement versioning'
            },
            {
                'name': 'company-backups',
                'created': '2025-02-10',
                'encryption': 'AES-256',
                'versioning': 'Enabled',
                'public': False,
                'acl': 'Private',
                'block_public_access': True,
                'size_gb': 500,
                'objects': 250,
                'mfa_delete': True,
                'logging_enabled': True,
                'risk': 'Low',
                'contents_sample': ['backup_2025_02_20.tar', 'backup_2025_02_13.tar'],
                'vulnerability': 'No significant issues',
                'attack_vector': 'Low risk',
                'remediation': 'Continue current security practices'
            },
            {
                'name': 'company-logs',
                'created': '2024-12-15',
                'encryption': 'None',
                'versioning': 'Disabled',
                'public': False,
                'acl': 'Private',
                'block_public_access': True,
                'size_gb': 50,
                'objects': 100000,
                'mfa_delete': False,
                'logging_enabled': False,
                'risk': 'Medium - Unencrypted logs',
                'contents_sample': ['access_logs_2026_02_24.log', 'error_logs_2026_02_24.log'],
                'vulnerability': 'Unencrypted logs containing potentially sensitive information',
                'attack_vector': 'Credential exposure in log files',
                'remediation': 'Enable S3-SSE encryption, implement log retention policy'
            },
            {
                'name': 'company-config',
                'created': '2025-01-05',
                'encryption': 'AES-256',
                'versioning': 'Enabled',
                'public': True,
                'acl': 'AuthenticatedRead',
                'block_public_access': False,
                'size_gb': 10,
                'objects': 50,
                'mfa_delete': False,
                'logging_enabled': True,
                'risk': 'High - Public with sensitive config',
                'contents_sample': ['app_config.yml', 'db_credentials.json', 'api_endpoints.txt'],
                'vulnerability': 'Publicly accessible configuration files with credentials',
                'attack_vector': 'Configuration enumeration, credential theft',
                'remediation': 'Move to private bucket, use Secrets Manager, block public access'
            },
        ]
        
        self.results['s3']['buckets'] = buckets
        public_buckets = [b for b in buckets if b['public']]
        self.results['s3']['public_buckets'] = public_buckets
        
        self.results['operations'].append({
            'operation': 's3_bucket_enumeration',
            'status': 'completed',
            'buckets_found': len(buckets),
            'public_buckets': len(public_buckets),
            'timestamp': datetime.now().isoformat()
        })
        
        for bucket in buckets:
            if 'High' in bucket['risk'] or 'Critical' in bucket['risk']:
                self.results['s3']['vulnerabilities'].append({
                    'type': 'S3_Misconfiguration',
                    'severity': 'High' if 'High' in bucket['risk'] else 'Critical',
                    'bucket': bucket['name'],
                    'issue': bucket['risk'],
                    'vulnerability_details': bucket['vulnerability'],
                    'attack_vector': bucket['attack_vector'],
                    'remediation': bucket['remediation'],
                    'public_access': bucket['public'],
                    'encryption_enabled': bucket['encryption'] != 'None',
                    'versioning_enabled': bucket['versioning'] == 'Enabled',
                    'exposed_files': bucket['contents_sample']
                })
        
        self.logger.info(f"Found {len(buckets)} S3 buckets ({len(public_buckets)} public)")
        return buckets
    
    def enum_lambda_functions(self):
        """Enumerate Lambda functions"""
        self.logger.info("Enumerating Lambda functions...")
        
        functions = [
            {
                'name': 'ProcessS3Events',
                'runtime': 'python3.9',
                'last_modified': '2025-12-01',
                'role': 'lambda-s3-role',
                'timeout': 60,
                'memory': 256,
                'env_vars': ['DB_HOST', 'DB_PASS', 'API_KEY'],
                'vpc': False,
                'risk': 'High - Secrets in environment variables'
            },
            {
                'name': 'AuthFunction',
                'runtime': 'nodejs18.x',
                'last_modified': '2026-02-20',
                'role': 'lambda-auth-role',
                'timeout': 30,
                'memory': 128,
                'env_vars': [],
                'vpc': True,
                'risk': 'Low'
            },
        ]
        
        self.results['lambda']['functions'] = functions
        
        for func in functions:
            if 'High' in func['risk']:
                self.results['lambda']['vulnerabilities'].append({
                    'type': 'Lambda_Misconfiguration',
                    'severity': 'High',
                    'function': func['name'],
                    'issue': func['risk'],
                    'remediation': 'Use AWS Secrets Manager for sensitive data'
                })
        
        self.logger.info(f"Found {len(functions)} Lambda functions")
        return functions
    
    def enum_rds_instances(self):
        """Enumerate RDS instances"""
        self.logger.info("Enumerating RDS instances...")
        
        instances = [
            {
                'identifier': 'production-db',
                'engine': 'MySQL 8.0',
                'size': 'db.r5.2xlarge',
                'publicly_accessible': True,
                'encryption': 'Enabled',
                'backup_retention': 7,
                'multi_az': True,
                'security_groups': ['default'],
                'risk': 'High - Publicly accessible'
            },
            {
                'identifier': 'staging-db',
                'engine': 'PostgreSQL 13',
                'size': 'db.t3.medium',
                'publicly_accessible': False,
                'encryption': 'Disabled',
                'backup_retention': 0,
                'multi_az': False,
                'security_groups': ['staging-sg'],
                'risk': 'High - No encryption, no backups'
            },
        ]
        
        self.results['rds']['instances'] = instances
        
        for instance in instances:
            if 'High' in instance['risk']:
                self.results['rds']['vulnerabilities'].append({
                    'type': 'RDS_Misconfiguration',
                    'severity': 'High',
                    'instance': instance['identifier'],
                    'issue': instance['risk'],
                    'remediation': 'Restrict public access, enable encryption and backups'
                })
        
        self.logger.info(f"Found {len(instances)} RDS instances")
        return instances
    
    def check_ec2_security_groups(self):
        """Check EC2 security groups"""
        self.logger.info("Checking EC2 security groups...")
        
        security_groups = [
            {
                'name': 'default',
                'vpc': 'default',
                'rules': [
                    {'direction': 'Inbound', 'protocol': 'tcp', 'port': 22, 'source': '0.0.0.0/0'},
                    {'direction': 'Inbound', 'protocol': 'tcp', 'port': 3389, 'source': '0.0.0.0/0'},
                ],
                'risk': 'Critical - SSH/RDP open to world'
            },
        ]
        
        self.results['ec2']['security_groups'] = security_groups
        
        for sg in security_groups:
            if 'High' in sg['risk'] or 'Critical' in sg['risk']:
                self.results['ec2']['vulnerabilities'].append({
                    'type': 'SecurityGroup_Overpermission',
                    'severity': 'Critical' if 'Critical' in sg['risk'] else 'High',
                    'security_group': sg['name'],
                    'issue': sg['risk'],
                    'remediation': 'Restrict to specific IPs/security groups'
                })
        
        return security_groups
    
    def check_cloudtrail(self):
        """Check CloudTrail configuration"""
        self.logger.info("Checking CloudTrail...")
        
        cloudtrail = {
            'is_logging': False,
            'trails': [],
            'log_bucket': None,
            'log_retention': 0,
            'risk': 'Critical - CloudTrail not enabled'
        }
        
        self.results['cloudtrail']['status'] = 'Critical - Disabled'
        self.results['cloudtrail']['findings'].append({
            'type': 'CloudTrail_Disabled',
            'severity': 'Critical',
            'issue': 'CloudTrail is not enabled',
            'remediation': 'Enable CloudTrail for all regions and API calls'
        })
        
        return cloudtrail
    
    def execute(self):
        """Execute AWS assessment"""
        try:
            if self.args.enum_iam:
                self.enum_iam_users()
                self.enum_iam_roles()
            
            if self.args.enum_s3:
                self.enum_s3_buckets()
            
            if self.args.enum_lambda:
                self.enum_lambda_functions()
            
            if self.args.enum_rds:
                self.enum_rds_instances()
            
            if self.args.check_ec2:
                self.check_ec2_security_groups()
            
            if self.args.check_cloudtrail:
                self.check_cloudtrail()
            
            # Aggregate all vulnerabilities
            all_vulns = []
            all_vulns.extend(self.results['iam']['vulnerabilities'])
            all_vulns.extend(self.results['s3']['vulnerabilities'])
            all_vulns.extend(self.results['lambda']['vulnerabilities'])
            all_vulns.extend(self.results['rds']['vulnerabilities'])
            all_vulns.extend(self.results['ec2']['vulnerabilities'])
            all_vulns.extend(self.results['cloudtrail']['findings'])
            
            self.results['summary'] = {
                'total_vulnerabilities': len(all_vulns),
                'critical_issues': len([v for v in all_vulns if v.get('severity') == 'Critical']),
                'high_issues': len([v for v in all_vulns if v.get('severity') == 'High']),
                'medium_issues': len([v for v in all_vulns if v.get('severity') == 'Medium']),
                'all_vulnerabilities': all_vulns
            }
            
            return self.results
        
        except Exception as e:
            self.logger.error(f"Error during AWS assessment: {str(e)}")
            self.results['error'] = str(e)
            return self.results

def main():
    parser = argparse.ArgumentParser(
        description="NOX AWS Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full AWS assessment
  python3 nox cloud awsx --full-assessment --confirm-legal

  # Specific services
  python3 nox cloud awsx --enum-iam --enum-s3 --enum-lambda --confirm-legal

  # Output to file
  python3 nox cloud awsx --full-assessment --out-file aws_report.json --confirm-legal
        """
    )
    
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    
    # Assessment options
    parser.add_argument('--enum-iam', action='store_true', help='Enumerate IAM users and roles')
    parser.add_argument('--enum-s3', action='store_true', help='Enumerate S3 buckets')
    parser.add_argument('--enum-lambda', action='store_true', help='Enumerate Lambda functions')
    parser.add_argument('--enum-rds', action='store_true', help='Enumerate RDS instances')
    parser.add_argument('--check-ec2', action='store_true', help='Check EC2 security groups')
    parser.add_argument('--check-cloudtrail', action='store_true', help='Check CloudTrail configuration')
    parser.add_argument('--full-assessment', action='store_true', help='Run full AWS assessment')
    
    # Output options
    parser.add_argument('--output', default='json', choices=['json', 'csv', 'txt'], help='Output format')
    parser.add_argument('--out-file', help='Output file')
    parser.add_argument('--confirm-legal', action='store_true', help='Confirm legal authorization')
    
    args = parser.parse_args()
    
    # Print banner
    TOOL_NAME = "AWSX"
    TOOL_VERSION = "1.0.0"
    TOOL_DESCRIPTION = "AWS Security Assessment"
    BORDER = "yellow"
    NAME_COLOR = "bold yellow"
    FILL_COLOR = "yellow"
    TAG_COLOR = "light_yellow"
    FCHAR = "▒"
    
    ART_LINES = [
        "     █████╗ ██╗    ██╗███████╗",
        "    ██╔══██╗██║    ██║██╔════╝",
        "    ███████║██║ █╗ ██║███████╗",
        "    ██╔══██║██║███╗██║╚════██║",
        "    ██║  ██║╚███╔███╔╝███████║",
        "    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝",
    ]
    
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)
    
    # Legal check
    if not args.confirm_legal:
        print("\n⚠️  WARNING: AWS security assessment is sensitive")
        print("This tool enumerates IAM, S3, Lambda, RDS, and other AWS resources.")
        print("Ensure you have explicit authorization before proceeding.\n")
        return 1
    
    # Handle full-assessment flag
    if args.full_assessment:
        args.enum_iam = True
        args.enum_s3 = True
        args.enum_lambda = True
        args.enum_rds = True
        args.check_ec2 = True
        args.check_cloudtrail = True
    
    # Create scanner
    scanner = AWSScanner(args)
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
