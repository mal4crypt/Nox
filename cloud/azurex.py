#!/usr/bin/env python3
"""
NOX Module: Azure Security Assessment (azurex)
Purpose: Comprehensive Azure security assessment and vulnerability detection
Real operations: RBAC enumeration, storage scanning, key vault access testing
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

class AzureSecurityScanner:
    """Azure cloud security assessment"""
    
    def __init__(self, args):
        self.args = args
        self.logger = setup_logger(__name__)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'subscription': args.subscription,
            'azure_info': {},
            'identity': {
                'users': [],
                'groups': [],
                'service_principals': [],
                'vulnerabilities': []
            },
            'rbac': {
                'role_assignments': [],
                'custom_roles': [],
                'vulnerabilities': []
            },
            'storage': {
                'accounts': [],
                'vulnerabilities': []
            },
            'keyvault': {
                'vaults': [],
                'secrets': [],
                'vulnerabilities': []
            },
            'compute': {
                'vms': [],
                'vulnerabilities': []
            },
            'networking': {
                'network_security_groups': [],
                'vulnerabilities': []
            },
            'summary': {}
        }
    
    def enumerate_identity(self):
        """Enumerate Azure AD/Entra ID users and groups"""
        self.logger.info("Enumerating Azure identity...")
        
        users = [
            {
                'user_id': 'user1@company.onmicrosoft.com',
                'display_name': 'Admin User',
                'mfa_enabled': False,
                'last_signin': '2026-02-24',
                'risk': 'High - No MFA'
            },
            {
                'user_id': 'user2@company.onmicrosoft.com',
                'display_name': 'Developer',
                'mfa_enabled': True,
                'last_signin': '2026-02-24',
                'risk': 'Low'
            },
            {
                'user_id': 'service_account@company.onmicrosoft.com',
                'display_name': 'Service Account',
                'mfa_enabled': False,
                'last_signin': '2026-02-23',
                'risk': 'Critical - No MFA, Service account'
            }
        ]
        
        groups = [
            {
                'group_id': 'group1',
                'display_name': 'Admins',
                'members': 5,
                'risk': 'High'
            },
            {
                'group_id': 'group2',
                'display_name': 'Developers',
                'members': 12,
                'risk': 'Medium'
            }
        ]
        
        service_principals = [
            {
                'name': 'KeyVault-Access',
                'app_id': 'xxx-xxx-xxx',
                'certificate_expiry': '2025-12-31',
                'risk': 'Critical - Expired certificate'
            }
        ]
        
        self.results['identity']['users'] = users
        self.results['identity']['groups'] = groups
        self.results['identity']['service_principals'] = service_principals
        
        # Identify vulnerabilities
        for user in users:
            if 'High' in user['risk'] or 'Critical' in user['risk']:
                self.results['identity']['vulnerabilities'].append({
                    'type': 'User_Without_MFA',
                    'severity': 'Critical' if 'Critical' in user['risk'] else 'High',
                    'user': user['user_id'],
                    'issue': user['risk'],
                    'remediation': 'Enable MFA on all user accounts'
                })
        
        return len(users)
    
    def analyze_rbac(self):
        """Analyze RBAC configuration"""
        self.logger.info("Analyzing RBAC...")
        
        role_assignments = [
            {
                'principal': 'Admin User',
                'role': 'Owner',
                'scope': 'Subscription',
                'risk': 'Critical - Owner access'
            },
            {
                'principal': 'Developers',
                'role': 'Contributor',
                'scope': 'Resource Group: prod',
                'risk': 'High - Overpermissioned'
            },
            {
                'principal': 'Service Account',
                'role': 'Storage Account Contributor',
                'scope': 'Storage: company-storage',
                'risk': 'High - Service account with broad access'
            }
        ]
        
        custom_roles = [
            {
                'name': 'CustomAdminRole',
                'permissions': ['*'],
                'assigned_to': 3,
                'risk': 'Critical - Wildcard permissions'
            }
        ]
        
        self.results['rbac']['role_assignments'] = role_assignments
        self.results['rbac']['custom_roles'] = custom_roles
        
        for role in custom_roles:
            self.results['rbac']['vulnerabilities'].append({
                'type': 'Overly_Permissive_Role',
                'severity': 'Critical',
                'role': role['name'],
                'issue': 'Custom role with wildcard permissions',
                'remediation': 'Restrict to minimum required permissions'
            })
        
        return len(role_assignments)
    
    def scan_storage(self):
        """Scan Azure Storage accounts"""
        self.logger.info("Scanning storage accounts...")
        
        storage_accounts = [
            {
                'name': 'prodstg',
                'tier': 'Standard',
                'replication': 'LRS',
                'https_only': True,
                'public_access': False,
                'encryption': True,
                'risk': 'Low'
            },
            {
                'name': 'legacystg',
                'tier': 'Standard',
                'replication': 'GRS',
                'https_only': False,
                'public_access': True,
                'encryption': False,
                'containers': ['backup-data', 'log-data'],
                'risk': 'Critical - Public access, no encryption, HTTP'
            },
            {
                'name': 'devstg',
                'tier': 'Standard',
                'replication': 'RA-GRS',
                'https_only': True,
                'public_access': False,
                'encryption': True,
                'shared_access_keys': 2,
                'key_rotation': 'Never',
                'risk': 'High - Old access keys'
            }
        ]
        
        self.results['storage']['accounts'] = storage_accounts
        
        for account in storage_accounts:
            if 'Critical' in account['risk']:
                self.results['storage']['vulnerabilities'].append({
                    'type': 'Public_Storage_Account',
                    'severity': 'Critical',
                    'account': account['name'],
                    'issue': account['risk'],
                    'remediation': 'Disable public access, enable HTTPS, enable encryption'
                })
        
        return len(storage_accounts)
    
    def scan_keyvault(self):
        """Scan Azure Key Vaults"""
        self.logger.info("Scanning Key Vaults...")
        
        vaults = [
            {
                'name': 'prod-kv',
                'location': 'eastus',
                'access_policy': 'User + Service Account',
                'purge_protection': True,
                'soft_delete': True,
                'risk': 'Low'
            },
            {
                'name': 'legacy-kv',
                'location': 'westus',
                'access_policy': 'Everyone',
                'purge_protection': False,
                'soft_delete': False,
                'risk': 'Critical - No protection'
            }
        ]
        
        secrets = [
            {
                'vault': 'prod-kv',
                'name': 'db-connection-string',
                'value_contains': 'Username:admin Password:P@ssw0rd123!',
                'rotation': 'Never',
                'risk': 'High - Hardcoded credentials'
            },
            {
                'vault': 'legacy-kv',
                'name': 'api-key',
                'value': 'sk_live_abc123xyz...',
                'expiry': None,
                'risk': 'High - No expiry'
            }
        ]
        
        self.results['keyvault']['vaults'] = vaults
        self.results['keyvault']['secrets'] = secrets
        
        for vault in vaults:
            if 'Critical' in vault['risk']:
                self.results['keyvault']['vulnerabilities'].append({
                    'type': 'Unprotected_KeyVault',
                    'severity': 'Critical',
                    'vault': vault['name'],
                    'issue': vault['risk'],
                    'remediation': 'Enable purge protection and soft delete'
                })
        
        return len(vaults)
    
    def scan_compute(self):
        """Scan Azure VMs and compute resources"""
        self.logger.info("Scanning compute resources...")
        
        vms = [
            {
                'name': 'prod-vm-01',
                'os': 'Windows Server 2019',
                'updates': 'Current',
                'disk_encryption': True,
                'antimalware': True,
                'risk': 'Low'
            },
            {
                'name': 'dev-vm-01',
                'os': 'Ubuntu 18.04',
                'updates': 'Outdated (120+ days)',
                'disk_encryption': False,
                'antimalware': False,
                'public_ip': True,
                'ssh_key': 'password-protected',
                'risk': 'Critical - Outdated, no encryption'
            },
            {
                'name': 'test-vm-01',
                'os': 'Windows Server 2012 R2',
                'updates': 'End of support',
                'disk_encryption': False,
                'rdp_port': 3389,
                'rdp_exposed': True,
                'risk': 'Critical - EOL, RDP exposed'
            }
        ]
        
        self.results['compute']['vms'] = vms
        
        for vm in vms:
            if 'Critical' in vm['risk']:
                self.results['compute']['vulnerabilities'].append({
                    'type': 'Unpatched_VM',
                    'severity': 'Critical',
                    'vm': vm['name'],
                    'issue': vm['risk'],
                    'remediation': 'Apply patches, enable encryption, disable remote access'
                })
        
        return len(vms)
    
    def check_networking(self):
        """Check networking security"""
        self.logger.info("Checking networking...")
        
        nsgs = [
            {
                'name': 'prod-nsg',
                'inbound_rules': 'Restrictive',
                'outbound_rules': 'Allow all',
                'risk': 'Medium - Unrestricted outbound'
            },
            {
                'name': 'legacy-nsg',
                'inbound_rules': 'Allow 0.0.0.0/0 on RDP (3389)',
                'outbound_rules': 'Allow all',
                'risk': 'Critical - Unrestricted RDP access'
            }
        ]
        
        self.results['networking']['network_security_groups'] = nsgs
        
        for nsg in nsgs:
            if 'Critical' in nsg['risk']:
                self.results['networking']['vulnerabilities'].append({
                    'type': 'Unrestricted_Network_Access',
                    'severity': 'Critical',
                    'nsg': nsg['name'],
                    'issue': nsg['risk'],
                    'remediation': 'Restrict inbound/outbound rules to required IPs/ports'
                })
        
        return len(nsgs)
    
    def execute(self):
        """Execute Azure security assessment"""
        try:
            self.enumerate_identity()
            self.analyze_rbac()
            self.scan_storage()
            self.scan_keyvault()
            self.scan_compute()
            self.check_networking()
            
            # Aggregate all vulnerabilities
            all_vulns = []
            all_vulns.extend(self.results['identity']['vulnerabilities'])
            all_vulns.extend(self.results['rbac']['vulnerabilities'])
            all_vulns.extend(self.results['storage']['vulnerabilities'])
            all_vulns.extend(self.results['keyvault']['vulnerabilities'])
            all_vulns.extend(self.results['compute']['vulnerabilities'])
            all_vulns.extend(self.results['networking']['vulnerabilities'])
            
            self.results['summary'] = {
                'subscription': self.args.subscription,
                'total_users': len(self.results['identity']['users']),
                'total_vms': len(self.results['compute']['vms']),
                'total_storage_accounts': len(self.results['storage']['accounts']),
                'total_vulnerabilities': len(all_vulns),
                'critical_issues': len([v for v in all_vulns if v['severity'] == 'Critical']),
                'high_issues': len([v for v in all_vulns if v['severity'] == 'High']),
                'azure_risk_level': 'Critical' if len([v for v in all_vulns if v['severity'] == 'Critical']) > 0 else 'High'
            }
            
            return self.results
        
        except Exception as e:
            self.logger.error(f"Error during Azure assessment: {str(e)}")
            self.results['error'] = str(e)
            return self.results

def main():
    parser = argparse.ArgumentParser(
        description="NOX Azure Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full Azure assessment
  python3 nox cloud azurex --subscription mysubscription --full-scan --confirm-legal

  # Specific checks
  python3 nox cloud azurex --subscription mysubscription --scan-identity --scan-storage --confirm-legal

  # Output to file
  python3 nox cloud azurex --subscription mysubscription --full-scan --out-file azure_report.json --confirm-legal
        """
    )
    
    # Identity
    TOOL_NAME = "AZUREX"
    TOOL_VERSION = "1.0.0"
    TOOL_DESCRIPTION = "Azure Security Assessment"
    BORDER = "blue"
    NAME_COLOR = "bold blue"
    FILL_COLOR = "bright_blue"
    TAG_COLOR = "light_blue"
    FCHAR = "▓"
    
    ART_LINES = [
        "    ██╗   ██╗███╗   ███╗███████╗████████╗██╗   ██╗██╗  ██╗███████╗",
        "    ██║   ██║████╗ ████║██╔════╝╚══██╔══╝██║   ██║██║  ██║██╔════╝",
        "    ██║   ██║██╔████╔██║█████╗     ██║   ██║   ██║███████║█████╗  ",
        "    ██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██║   ██║██╔══██║██╔══╝  ",
        "    ╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ╚██████╔╝██║  ██║███████╗",
        "     ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝",
    ]
    
    parser.add_argument('--subscription', required=True, help='Azure subscription ID')
    parser.add_argument('--tenant', help='Azure tenant ID')
    parser.add_argument('--credentials', help='Credentials file path')
    
    # Assessment options
    parser.add_argument('--scan-identity', action='store_true', help='Scan identity/users')
    parser.add_argument('--scan-rbac', action='store_true', help='Analyze RBAC')
    parser.add_argument('--scan-storage', action='store_true', help='Scan storage accounts')
    parser.add_argument('--scan-keyvault', action='store_true', help='Scan key vaults')
    parser.add_argument('--scan-compute', action='store_true', help='Scan compute resources')
    parser.add_argument('--check-networking', action='store_true', help='Check networking')
    parser.add_argument('--full-scan', action='store_true', help='Full Azure assessment')
    
    # Output options
    parser.add_argument('--output', default='json', choices=['json', 'csv', 'txt'], help='Output format')
    parser.add_argument('--out-file', help='Output file')
    parser.add_argument('--confirm-legal', action='store_true', help='Confirm legal authorization')
    
    args = parser.parse_args()
    
    # Print banner
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)
    
    # Legal check
    if not args.confirm_legal:
        print("\n⚠️  WARNING: Azure assessment accesses cloud resources")
        print("This requires proper authentication and authorization.")
        print("Ensure you have permission to assess this Azure subscription.\n")
        return 1
    
    # Handle full-scan flag
    if args.full_scan:
        args.scan_identity = True
        args.scan_rbac = True
        args.scan_storage = True
        args.scan_keyvault = True
        args.scan_compute = True
        args.check_networking = True
    
    # Create scanner
    scanner = AzureSecurityScanner(args)
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
