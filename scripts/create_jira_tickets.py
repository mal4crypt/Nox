#!/usr/bin/env python3
"""
NOX to JIRA Integration Script
Convert NOX vulnerability findings into JIRA tickets
"""

import json
import sys
import argparse
from datetime import datetime

def load_findings(filepath):
    """Load NOX findings from JSON file"""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"[!] Error: File not found - {filepath}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"[!] Error: Invalid JSON in {filepath}")
        sys.exit(1)

def severity_to_priority(severity):
    """Map vulnerability severity to JIRA priority"""
    severity_map = {
        'critical': 'Blocker',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'info': 'Low'
    }
    return severity_map.get(severity.lower(), 'Medium')

def create_jira_issue(finding, project_key, assignee):
    """Create JIRA issue data structure"""
    
    severity = finding.get('severity', 'Medium')
    priority = severity_to_priority(severity)
    
    # Build description from finding details
    description = f"""
h3. Vulnerability Details
* *Service:* {finding.get('service', 'Unknown')}
* *CVE:* {finding.get('cve', 'N/A')}
* *Severity:* {severity}
* *CVSS Score:* {finding.get('cvss_score', 'N/A')}
* *Found Date:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

h3. Description
{finding.get('description', 'No description available')}

h3. Technical Details
* *Affected Asset:* {finding.get('target', 'Unknown')}
* *Port:* {finding.get('port', 'Unknown')}
* *Protocol:* {finding.get('protocol', 'Unknown')}

h3. Remediation
{finding.get('remediation', 'No remediation guidance available')}

h3. Risk Assessment
{finding.get('risk_assessment', 'No risk assessment available')}
"""
    
    issue = {
        'fields': {
            'project': {'key': project_key},
            'summary': f"[{severity.upper()}] {finding.get('vulnerability_name', 'Unknown Vulnerability')}",
            'description': description,
            'priority': {'name': priority},
            'labels': [
                f"severity_{severity.lower()}",
                f"service_{finding.get('service', 'unknown').lower()}",
                'nox-automated'
            ],
            'customfield_security_impact': finding.get('impact', 'Unknown'),
        }
    }
    
    if assignee:
        issue['fields']['assignee'] = {'name': assignee}
    
    return issue

def generate_jira_import_file(findings, project_key, assignee, output_file=None):
    """Generate JIRA import JSON file"""
    
    issues = []
    
    vulnerabilities = findings.get('vulnerabilities', [])
    if not vulnerabilities and isinstance(findings, dict):
        # Sometimes findings is just a list or single finding
        if isinstance(findings, list):
            vulnerabilities = findings
        else:
            vulnerabilities = [findings]
    
    print(f"[*] Processing {len(vulnerabilities)} vulnerabilities...")
    
    for finding in vulnerabilities:
        if isinstance(finding, dict):
            issue = create_jira_issue(finding, project_key, assignee)
            issues.append(issue)
    
    output = {
        'issues': issues,
        'meta': {
            'generated_by': 'NOX JIRA Integration',
            'generated_date': datetime.now().isoformat(),
            'total_issues': len(issues)
        }
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"[+] JIRA import file created: {output_file}")
    
    return output

def print_jira_commands(findings_file, project_key):
    """Print commands for JIRA CLI import"""
    
    print("\n" + "="*60)
    print("JIRA Import Instructions")
    print("="*60)
    print("\n[1] Using JIRA REST API:")
    print(f"""
curl -X POST \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_TOKEN" \\
  https://your-jira-instance.com/rest/api/3/issues/import \\
  -d @jira_import.json
""")
    
    print("[2] Using JIRA Command Line:")
    print(f"""
jira_cli --action createIssues \\
  --project {project_key} \\
  --file jira_import.json
""")
    
    print("[3] Using Jira Python Library:")
    print(f"""
from jira import JIRA

jira = JIRA('https://your-jira-instance.com', auth=('user', 'token'))

with open('jira_import.json') as f:
    issues = json.load(f)['issues']

for issue_data in issues:
    jira.create_issue(**issue_data)
""")

def main():
    parser = argparse.ArgumentParser(
        description="Convert NOX findings to JIRA tickets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate JIRA import file
  python3 scripts/create_jira_tickets.py --findings scan.json --project SEC
  
  # Specify assignee
  python3 scripts/create_jira_tickets.py --findings scan.json --project SEC --assignee john.doe
  
  # Specify output file
  python3 scripts/create_jira_tickets.py --findings scan.json --project SEC --output tickets.json
        """
    )
    
    parser.add_argument('--findings', required=True, help='NOX findings JSON file')
    parser.add_argument('--project', required=True, help='JIRA project key (e.g., SEC)')
    parser.add_argument('--assignee', help='Default assignee for tickets')
    parser.add_argument('--output', help='Output JIRA import file (default: jira_import.json)')
    parser.add_argument('--show-commands', action='store_true', help='Show JIRA import commands')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without creating file')
    
    args = parser.parse_args()
    
    output_file = args.output or 'jira_import.json'
    
    print("\n" + "="*60)
    print("NOX → JIRA Integration")
    print("="*60 + "\n")
    
    # Load findings
    print(f"[*] Loading findings from {args.findings}...")
    findings = load_findings(args.findings)
    print("[+] Findings loaded successfully")
    
    # Generate JIRA import
    print(f"[*] Generating JIRA issues for project '{args.project}'...")
    import_data = generate_jira_import_file(
        findings,
        args.project,
        args.assignee,
        output_file if not args.dry_run else None
    )
    
    print(f"[+] Total issues generated: {len(import_data['issues'])}")
    
    # Show statistics
    print("\n" + "─"*60)
    print("Issue Summary:")
    print("─"*60)
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    for issue_data in import_data['issues']:
        # Extract severity from summary
        summary = issue_data['fields']['summary']
        if '[CRITICAL]' in summary.upper():
            severity_counts['critical'] += 1
        elif '[HIGH]' in summary.upper():
            severity_counts['high'] += 1
        elif '[MEDIUM]' in summary.upper():
            severity_counts['medium'] += 1
        elif '[LOW]' in summary.upper():
            severity_counts['low'] += 1
        else:
            severity_counts['info'] += 1
    
    print(f"Critical:  {severity_counts['critical']} issues")
    print(f"High:      {severity_counts['high']} issues")
    print(f"Medium:    {severity_counts['medium']} issues")
    print(f"Low:       {severity_counts['low']} issues")
    print(f"Info:      {severity_counts['info']} issues")
    
    print("\n" + "─"*60)
    
    if args.show_commands or args.dry_run:
        print_jira_commands(args.findings, args.project)
    
    if not args.dry_run:
        print(f"\n[+] JIRA import file created: {output_file}")
        print("\n[*] Next steps:")
        print(f"    1. Use your JIRA tool to import {output_file}")
        print(f"    2. Or use: --show-commands flag to see import options")
        print(f"    3. Configure JIRA authentication if needed")
    else:
        print("\n[*] DRY RUN - No file created")
        print("[*] Use --dry-run false to create actual file")
    
    print("\n✅ JIRA integration ready!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
