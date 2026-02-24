#!/usr/bin/env python3
"""
Custom Script: Alert on Critical Findings

Usage:
    python3 scripts/alert_if_critical.py --input scan.json
    python3 scripts/alert_if_critical.py --input scan.json --email admin@company.com
    python3 scripts/alert_if_critical.py --input scan.json --slack-webhook https://hooks.slack.com/...
"""

import json
import sys
import argparse
import subprocess
from pathlib import Path

def check_critical_findings(input_file, email=None, slack_webhook=None):
    """Check for critical findings and send alerts"""
    
    # Load scan results
    with open(input_file) as f:
        data = json.load(f)
    
    vulns = data.get("vulnerabilities", [])
    target = data.get("target", "Unknown")
    
    # Find critical vulnerabilities
    critical_vulns = [v for v in vulns if v.get("severity") == "Critical"]
    high_vulns = [v for v in vulns if v.get("severity") == "High"]
    
    print("╔════════════════════════════════════════════════════════╗")
    print("║       CRITICAL FINDINGS ALERT SYSTEM                   ║")
    print("╚════════════════════════════════════════════════════════╝\n")
    
    print(f"Target: {target}")
    print(f"Critical Issues: {len(critical_vulns)}")
    print(f"High Issues: {len(high_vulns)}\n")
    
    # Alert if critical findings
    if critical_vulns:
        print("🚨 CRITICAL VULNERABILITIES DETECTED!\n")
        
        for vuln in critical_vulns:
            print(f"  • {vuln.get('cve', 'Unknown')}")
            print(f"    Service: {vuln.get('service', 'Unknown')}")
            print(f"    Impact: {vuln.get('severity', 'Unknown')}\n")
        
        # Send email alert if specified
        if email:
            send_email_alert(target, critical_vulns, email)
        
        # Send Slack alert if webhook provided
        if slack_webhook:
            send_slack_alert(target, critical_vulns, slack_webhook)
        
        return 1  # Exit with error code
    else:
        print("✅ No critical vulnerabilities detected")
        return 0

def send_email_alert(target, vulns, email):
    """Send email alert"""
    print(f"\n[*] Sending email alert to {email}...")
    
    subject = f"🚨 CRITICAL: {len(vulns)} vulnerabilities found on {target}"
    body = f"""CRITICAL VULNERABILITIES DETECTED

Target: {target}
Critical Issues: {len(vulns)}

Vulnerabilities:
"""
    
    for vuln in vulns:
        body += f"\n• {vuln.get('cve', 'Unknown')} - {vuln.get('service', 'Unknown')}"
    
    body += "\n\nImmediate action required!"
    
    # Use sendmail or mail command
    try:
        result = subprocess.run(
            ['mail', '-s', subject, email],
            input=body.encode(),
            capture_output=True
        )
        if result.returncode == 0:
            print(f"[+] Alert email sent to {email}")
        else:
            print(f"[-] Failed to send email alert")
    except Exception as e:
        print(f"[-] Email error: {e}")

def send_slack_alert(target, vulns, webhook_url):
    """Send Slack alert"""
    print(f"\n[*] Sending Slack alert...")
    
    message = {
        "text": f"🚨 CRITICAL: {len(vulns)} vulnerabilities found on {target}",
        "attachments": [
            {
                "color": "danger",
                "title": f"Security Alert - {target}",
                "fields": [
                    {
                        "title": "Critical Vulnerabilities",
                        "value": str(len(vulns)),
                        "short": True
                    },
                    {
                        "title": "CVEs Found",
                        "value": ", ".join([v.get('cve', 'Unknown') for v in vulns[:5]]),
                        "short": False
                    },
                    {
                        "title": "Action Required",
                        "value": "Immediate investigation and remediation needed",
                        "short": False
                    }
                ]
            }
        ]
    }
    
    import urllib.request
    import json
    
    try:
        data = json.dumps(message).encode('utf-8')
        req = urllib.request.Request(webhook_url, data=data)
        req.add_header('Content-Type', 'application/json')
        
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print("[+] Slack alert sent")
            else:
                print(f"[-] Failed to send Slack alert: {response.status}")
    except Exception as e:
        print(f"[-] Slack error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Alert on critical findings from NOX scans")
    parser.add_argument("--input", required=True, help="Input JSON file from NOX scan")
    parser.add_argument("--email", help="Email address to send alerts to")
    parser.add_argument("--slack-webhook", help="Slack webhook URL for alerts")
    
    args = parser.parse_args()
    
    if not Path(args.input).exists():
        print(f"❌ Error: File not found: {args.input}")
        sys.exit(1)
    
    exit_code = check_critical_findings(args.input, args.email, args.slack_webhook)
    sys.exit(exit_code)
