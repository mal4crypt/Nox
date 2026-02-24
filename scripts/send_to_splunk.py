#!/usr/bin/env python3
"""
NOX to Splunk Integration Script
Forward NOX findings to Splunk HEC (HTTP Event Collector)
"""

import json
import sys
import argparse
import requests
from datetime import datetime
from urllib.parse import urljoin

class SplunkHEC:
    """Splunk HTTP Event Collector client"""
    
    def __init__(self, hec_url, hec_token, verify_ssl=True):
        self.hec_url = hec_url
        self.hec_token = hec_token
        self.verify_ssl = verify_ssl
        self.endpoint = urljoin(self.hec_url, '/services/collector')
        self.headers = {
            'Authorization': f'Splunk {self.hec_token}',
            'Content-Type': 'application/json'
        }
    
    def send_event(self, event_data, sourcetype='nox:vulnerability', source='nox'):
        """Send single event to Splunk HEC"""
        
        event = {
            'time': datetime.now().timestamp(),
            'source': source,
            'sourcetype': sourcetype,
            'event': event_data
        }
        
        try:
            response = requests.post(
                self.endpoint,
                json=event,
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                return True, "Event sent successfully"
            else:
                return False, f"HTTP {response.status_code}: {response.text}"
        
        except requests.exceptions.RequestException as e:
            return False, f"Connection error: {str(e)}"
    
    def send_batch(self, events, sourcetype='nox:vulnerability', source='nox'):
        """Send multiple events to Splunk HEC"""
        
        results = []
        
        for event_data in events:
            success, message = self.send_event(
                event_data,
                sourcetype=sourcetype,
                source=source
            )
            results.append({
                'success': success,
                'message': message,
                'event': event_data.get('vulnerability_name', 'Unknown')
            })
        
        return results

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

def format_for_splunk(findings):
    """Format NOX findings for Splunk ingestion"""
    
    events = []
    
    vulnerabilities = findings.get('vulnerabilities', [])
    if not vulnerabilities and isinstance(findings, dict):
        if isinstance(findings, list):
            vulnerabilities = findings
        else:
            vulnerabilities = [findings]
    
    for vuln in vulnerabilities:
        event = {
            'timestamp': datetime.now().isoformat(),
            'vulnerability_name': vuln.get('vulnerability_name', 'Unknown'),
            'severity': vuln.get('severity', 'Medium'),
            'service': vuln.get('service', 'Unknown'),
            'target': vuln.get('target', 'Unknown'),
            'port': vuln.get('port', 'Unknown'),
            'protocol': vuln.get('protocol', 'Unknown'),
            'cve': vuln.get('cve', 'N/A'),
            'cvss_score': vuln.get('cvss_score', 'N/A'),
            'description': vuln.get('description', ''),
            'impact': vuln.get('impact', 'Unknown'),
            'remediation': vuln.get('remediation', ''),
            'risk_assessment': vuln.get('risk_assessment', ''),
            'evidence': vuln.get('evidence', []),
            'tags': [
                f"severity_{vuln.get('severity', 'unknown').lower()}",
                f"service_{vuln.get('service', 'unknown').lower()}",
                'nox-scan'
            ]
        }
        events.append(event)
    
    return events

def test_connection(hec_url, hec_token, verify_ssl=True):
    """Test Splunk HEC connectivity"""
    
    hec = SplunkHEC(hec_url, hec_token, verify_ssl)
    test_event = {
        'test': True,
        'message': 'NOX Splunk integration test',
        'timestamp': datetime.now().isoformat()
    }
    
    success, message = hec.send_event(test_event, sourcetype='nox:test')
    return success, message

def main():
    parser = argparse.ArgumentParser(
        description="Forward NOX findings to Splunk HEC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send findings to Splunk
  python3 scripts/send_to_splunk.py \\
    --findings scan.json \\
    --hec-url https://splunk-server:8088 \\
    --hec-token YOUR-HEC-TOKEN
  
  # Test connection first
  python3 scripts/send_to_splunk.py \\
    --hec-url https://splunk-server:8088 \\
    --hec-token YOUR-HEC-TOKEN \\
    --test
  
  # Skip SSL verification (testing only)
  python3 scripts/send_to_splunk.py \\
    --findings scan.json \\
    --hec-url https://splunk-server:8088 \\
    --hec-token YOUR-HEC-TOKEN \\
    --skip-ssl-verify
        """
    )
    
    parser.add_argument('--findings', help='NOX findings JSON file')
    parser.add_argument('--hec-url', required=True, help='Splunk HEC URL (e.g., https://splunk:8088)')
    parser.add_argument('--hec-token', required=True, help='Splunk HEC token')
    parser.add_argument('--test', action='store_true', help='Test connection only')
    parser.add_argument('--skip-ssl-verify', action='store_true', help='Skip SSL certificate verification')
    parser.add_argument('--sourcetype', default='nox:vulnerability', help='Splunk source type')
    parser.add_argument('--source', default='nox', help='Splunk source')
    parser.add_argument('--dry-run', action='store_true', help='Show events without sending')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("NOX → Splunk Integration")
    print("="*60 + "\n")
    
    # Test connection if requested
    if args.test:
        print("[*] Testing Splunk HEC connection...")
        success, message = test_connection(
            args.hec_url,
            args.hec_token,
            verify_ssl=not args.skip_ssl_verify
        )
        
        if success:
            print("[+] ✅ Connection successful!")
            print(f"    Message: {message}")
        else:
            print("[!] ❌ Connection failed!")
            print(f"    Error: {message}")
            return 1
    
    # Check if findings file is specified
    if not args.findings and not args.test:
        parser.print_help()
        return 1
    
    if args.findings:
        print(f"[*] Loading findings from {args.findings}...")
        findings = load_findings(args.findings)
        print("[+] Findings loaded successfully")
        
        # Format for Splunk
        print("[*] Formatting events for Splunk...")
        events = format_for_splunk(findings)
        print(f"[+] {len(events)} events formatted")
        
        # Show preview
        if events:
            print("\n" + "─"*60)
            print("Event Preview (first event):")
            print("─"*60)
            print(json.dumps(events[0], indent=2))
        
        if args.dry_run:
            print("\n[*] DRY RUN - Events formatted but not sent")
            print(f"[*] Total events that would be sent: {len(events)}")
            return 0
        
        # Send to Splunk
        print("\n[*] Sending events to Splunk HEC...")
        hec = SplunkHEC(
            args.hec_url,
            args.hec_token,
            verify_ssl=not args.skip_ssl_verify
        )
        
        results = hec.send_batch(
            events,
            sourcetype=args.sourcetype,
            source=args.source
        )
        
        # Display results
        print("\n" + "─"*60)
        print("Splunk Send Results:")
        print("─"*60)
        
        successful = sum(1 for r in results if r['success'])
        failed = len(results) - successful
        
        print(f"Successful: {successful}/{len(results)}")
        print(f"Failed:     {failed}/{len(results)}")
        
        if failed > 0:
            print("\nFailed events:")
            for result in results:
                if not result['success']:
                    print(f"  - {result['event']}: {result['message']}")
        
        print("\n" + "─"*60)
        print("Splunk Queries:")
        print("─"*60)
        
        print("\nView all NOX events:")
        print("  sourcetype=nox:vulnerability")
        
        print("\nView critical findings:")
        print("  sourcetype=nox:vulnerability severity=critical")
        
        print("\nView by service:")
        print("  sourcetype=nox:vulnerability | stats count by service")
        
        print("\nView by severity:")
        print("  sourcetype=nox:vulnerability | stats count by severity")
        
        print("\nTimeline of findings:")
        print("  sourcetype=nox:vulnerability | timechart count by severity")
        
        print("\n✅ Splunk integration complete!")
        
        if successful == len(results):
            return 0
        else:
            return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
