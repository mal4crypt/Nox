# NOX Integration Guide - Enterprise Deployments

## Overview

NOX supports integration with **enterprise security tools** and **custom automation**. This guide covers 5 major integration patterns.

---

## 1. JIRA Ticket Generation

### Quick Start
```bash
python3 nox vuln scanx --target 192.168.1.1 --out-file scan.json --confirm-legal
python3 scripts/create_jira_tickets.py --findings scan.json --project SEC --assignee security-team
```

### Integration Patterns

**Pattern 1: Automatic Ticket Creation**
```bash
#!/bin/bash
# Create JIRA tickets for all critical findings

python3 scripts/create_jira_tickets.py \
  --findings scan.json \
  --project SEC \
  --assignee john.doe \
  --output jira_import.json

# Import via REST API
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JIRA_TOKEN" \
  https://jira.company.com/rest/api/3/issues/import \
  -d @jira_import.json
```

**Pattern 2: Conditional Ticket Creation**
```bash
#!/bin/bash
# Only create tickets for critical/high severity

python3 scripts/create_jira_tickets.py \
  --findings scan.json \
  --project SEC \
  --assignee security-team \
  --severity critical,high \
  --output critical_tickets.json
```

**Pattern 3: JIRA Python Library Integration**
```python
#!/usr/bin/env python3
from jira import JIRA
import json

jira = JIRA('https://jira.company.com', auth=('user', 'token'))

with open('jira_import.json') as f:
    data = json.load(f)

created = []
for issue_dict in data['issues']:
    issue = jira.create_issue(**issue_dict['fields'])
    created.append(issue.key)
    print(f"[+] Created {issue.key}")

print(f"[+] Created {len(created)} JIRA tickets")
```

### Key Features
- ✅ Automatic severity mapping
- ✅ Custom assignee support
- ✅ Priority mapping (Critical → Blocker, High → High, etc.)
- ✅ Labels and tagging
- ✅ Evidence attachment support
- ✅ Dry-run mode for preview

---

## 2. Splunk Integration

### Quick Start
```bash
# Test connection
python3 scripts/send_to_splunk.py \
  --hec-url https://splunk.company.com:8088 \
  --hec-token abc123def456 \
  --test

# Send findings
python3 scripts/send_to_splunk.py \
  --findings scan.json \
  --hec-url https://splunk.company.com:8088 \
  --hec-token abc123def456
```

### Integration Patterns

**Pattern 1: Real-Time Monitoring**
```bash
#!/bin/bash
# Continuous scanning with Splunk forwarding

while true; do
  TIMESTAMP=$(date +%s)
  
  python3 nox vuln scanx --target 192.168.1.0/24 \
    --out-file "scan_$TIMESTAMP.json" \
    --confirm-legal
  
  python3 scripts/send_to_splunk.py \
    --findings "scan_$TIMESTAMP.json" \
    --hec-url https://splunk.company.com:8088 \
    --hec-token $HEC_TOKEN
  
  sleep 3600  # Scan hourly
done
```

**Pattern 2: Splunk Dashboards**
```
[Dashboard: NOX Security Findings]

Row 1: Key Metrics
- Total Vulnerabilities: | stats count
- Critical Issues: | where severity=critical
- Services at Risk: | stats dc(service)

Row 2: Findings Timeline
- | timechart count by severity

Row 3: Services Analysis
- | stats count by service, severity
```

**Pattern 3: Splunk Alerts**
```
Alert: Critical Vulnerability Found
Query: sourcetype=nox:vulnerability severity=critical
Condition: count > 0
Actions: 
  - Send email to security@company.com
  - Trigger webhook to ServiceNow
  - Page on-call security engineer
```

### Setup Instructions

**1. Enable Splunk HEC**
```
Settings → Data Inputs → HTTP Event Collector
→ Create New Token
→ Copy token value
```

**2. Create Index (Optional)**
```spl
New Index: nox_vulnerabilities
Max KB/day: 100000
Retention: 90 days
```

**3. Configure NOX**
```bash
export SPLUNK_HEC_URL="https://splunk.company.com:8088"
export SPLUNK_HEC_TOKEN="your-hec-token"

python3 scripts/send_to_splunk.py \
  --findings scan.json \
  --hec-url $SPLUNK_HEC_URL \
  --hec-token $SPLUNK_HEC_TOKEN
```

### Splunk Queries

```spl
# View all NOX findings
sourcetype=nox:vulnerability

# Critical findings only
sourcetype=nox:vulnerability severity=critical

# Vulnerabilities by service
sourcetype=nox:vulnerability | stats count by service

# CVSS score analysis
sourcetype=nox:vulnerability | stats avg(cvss_score), max(cvss_score) by service

# Timeline
sourcetype=nox:vulnerability | timechart count by severity

# Service impact
sourcetype=nox:vulnerability | table target, port, service, severity, cve

# Trending
sourcetype=nox:vulnerability | stats count by severity, _time
```

---

## 3. Custom API Integration

### Pattern: Forward to Custom API
```python
#!/usr/bin/env python3
"""Forward NOX results to custom API"""

import json
import requests

def send_to_api(findings_file, api_endpoint):
    with open(findings_file) as f:
        findings = json.load(f)
    
    for vuln in findings['vulnerabilities']:
        # Transform for your API
        payload = {
            'vulnerability': vuln['vulnerability_name'],
            'severity': vuln['severity'],
            'target': vuln['target'],
            'cve': vuln['cve'],
            'description': vuln['description']
        }
        
        response = requests.post(api_endpoint, json=payload)
        print(f"[+] Sent {vuln['vulnerability_name']}: {response.status_code}")

if __name__ == "__main__":
    send_to_api('scan.json', 'https://api.company.com/vulnerabilities')
```

---

## 4. Workflow Automation

### Pattern: Multi-Tool Workflow
```bash
#!/bin/bash
# Orchestrate multiple tools with custom logic

set -e  # Exit on error

TARGET=$1
REPORT_DIR="./report_$(date +%s)"
mkdir -p "$REPORT_DIR"

echo "[1] Starting reconnaissance..."
python3 nox recon subx --domain "$TARGET" \
  --out-file "$REPORT_DIR/subdomains.json" --confirm-legal

echo "[2] Scanning for vulnerabilities..."
python3 nox vuln scanx --target "$TARGET" \
  --out-file "$REPORT_DIR/scan.json" --confirm-legal

echo "[3] Testing SQL injection..."
python3 nox webpwn sqlix --url "http://$TARGET" \
  --out-file "$REPORT_DIR/sqli.json" --confirm-legal

echo "[4] Analyzing findings..."
python3 scripts/analyze_vulnerabilities.py \
  --input "$REPORT_DIR/scan.json" \
  --output "$REPORT_DIR/analysis.json"

echo "[5] Creating JIRA tickets..."
python3 scripts/create_jira_tickets.py \
  --findings "$REPORT_DIR/analysis.json" \
  --project SEC \
  --output "$REPORT_DIR/jira_issues.json"

echo "[6] Sending to Splunk..."
python3 scripts/send_to_splunk.py \
  --findings "$REPORT_DIR/analysis.json" \
  --hec-url https://splunk:8088 \
  --hec-token $HEC_TOKEN

echo "[7] Generating final report..."
python3 nox report renderx \
  --findings "$REPORT_DIR/analysis.json" \
  --template technical \
  --format pdf \
  --out-file "$REPORT_DIR/final_report.pdf" \
  --confirm-legal

echo "[+] Assessment complete: $REPORT_DIR/"
```

---

## 5. CI/CD Pipeline Integration

### GitLab CI Example
```yaml
# .gitlab-ci.yml
stages:
  - scan
  - analyze
  - report

scan:
  stage: scan
  script:
    - python3 nox vuln scanx --target $TARGET --out-file scan.json --confirm-legal
  artifacts:
    paths:
      - scan.json

analyze:
  stage: analyze
  dependencies:
    - scan
  script:
    - python3 scripts/analyze_vulnerabilities.py --input scan.json
    - python3 scripts/create_jira_tickets.py --findings scan.json --project SEC
  artifacts:
    paths:
      - scan_analysis.json

report:
  stage: report
  dependencies:
    - analyze
  script:
    - python3 scripts/send_to_splunk.py --findings scan.json --hec-url $SPLUNK_URL
    - python3 scripts/alert_if_critical.py --findings scan.json --email security@company.com
```

### GitHub Actions Example
```yaml
# .github/workflows/nox-scan.yml
name: NOX Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run NOX scan
        run: |
          python3 nox vuln scanx --target ${{ secrets.TARGET }} \
            --out-file scan.json --confirm-legal
      
      - name: Analyze findings
        run: |
          python3 scripts/analyze_vulnerabilities.py --input scan.json
      
      - name: Create JIRA tickets
        run: |
          python3 scripts/create_jira_tickets.py \
            --findings scan.json \
            --project SEC \
            --assignee security-team
        env:
          JIRA_TOKEN: ${{ secrets.JIRA_TOKEN }}
      
      - name: Send to Splunk
        run: |
          python3 scripts/send_to_splunk.py \
            --findings scan.json \
            --hec-url ${{ secrets.SPLUNK_URL }} \
            --hec-token ${{ secrets.SPLUNK_TOKEN }}
      
      - name: Alert on critical findings
        run: |
          python3 scripts/alert_if_critical.py \
            --findings scan.json \
            --email security@company.com
```

---

## 6. Advanced Integration Examples

### Example 1: ServiceNow Integration
```python
#!/usr/bin/env python3
"""NOX to ServiceNow Incident Creation"""

from pysnow import Client
import json

def create_servicenow_incident(finding, instance, table='incident'):
    client = Client(host=instance, user='admin', password='pass')
    
    incident = {
        'short_description': f"[{finding['severity']}] {finding['vulnerability_name']}",
        'description': finding['description'],
        'impact': 2 if finding['severity'] == 'critical' else 3,
        'urgency': 2 if finding['severity'] == 'critical' else 3,
        'priority': 2 if finding['severity'] == 'critical' else 3,
        'category': 'Security',
        'subcategory': 'Vulnerability Management',
        'cmdb_ci': finding['target']
    }
    
    request = client.insert(table=table, payload=incident)
    print(f"[+] Created incident: {request['sys_id']}")

# Usage
with open('scan.json') as f:
    findings = json.load(f)

for vuln in findings['vulnerabilities']:
    if vuln['severity'] in ['critical', 'high']:
        create_servicenow_incident(vuln, 'your-instance.service-now.com')
```

### Example 2: Slack Notifications
```python
#!/usr/bin/env python3
"""NOX to Slack Notifications"""

import json
import requests

def send_slack_notification(findings_file, webhook_url):
    with open(findings_file) as f:
        findings = json.load(f)
    
    critical = [v for v in findings['vulnerabilities'] if v['severity'] == 'critical']
    
    if critical:
        message = {
            'text': f"🚨 {len(critical)} Critical Vulnerabilities Found",
            'blocks': [
                {
                    'type': 'header',
                    'text': {'type': 'plain_text', 'text': '🚨 Critical Findings'}
                },
                *[
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': f"*{v['vulnerability_name']}*\nTarget: {v['target']}\nCVE: {v['cve']}"
                        }
                    } for v in critical
                ]
            ]
        }
        
        requests.post(webhook_url, json=message)
        print(f"[+] Slack notification sent")

# Usage
send_slack_notification('scan.json', 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL')
```

### Example 3: Metasploit Integration
```python
#!/usr/bin/env python3
"""NOX to Metasploit Resource Script"""

import json

def generate_metasploit_rc(findings_file, output_file='exploit.rc'):
    with open(findings_file) as f:
        findings = json.load(f)
    
    rc_content = """
# Metasploit Resource Script - Generated by NOX

# Database setup
db_connect postgresql://msf:password@localhost/msf

# Create workspace
workspace -a nox_assessment

"""
    
    for vuln in findings['vulnerabilities']:
        if vuln['service'] == 'Apache' and 'shellshock' in vuln['vulnerability_name'].lower():
            rc_content += f"""
# Exploit: {vuln['vulnerability_name']}
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOST {vuln['target']}
set RPORT {vuln['port']}
set LHOST YOUR_IP
exploit
"""
    
    with open(output_file, 'w') as f:
        f.write(rc_content)
    
    print(f"[+] Metasploit RC script generated: {output_file}")

# Usage
generate_metasploit_rc('scan.json')
```

---

## Environment Variables

```bash
# Splunk Integration
export SPLUNK_HEC_URL="https://splunk.company.com:8088"
export SPLUNK_HEC_TOKEN="abc123def456"

# JIRA Integration
export JIRA_URL="https://jira.company.com"
export JIRA_TOKEN="your-api-token"
export JIRA_PROJECT="SEC"

# Slack Integration
export SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Email Integration
export SMTP_SERVER="mail.company.com"
export SMTP_PORT="587"
export SMTP_USER="security@company.com"
export SMTP_PASSWORD="password"
```

---

## Best Practices

✅ **Always use `--confirm-legal`** flag - ensures legal compliance
✅ **Test integrations** with `--test` or `--dry-run` flags first
✅ **Use environment variables** for sensitive credentials
✅ **Enable SSL verification** in production (`--skip-ssl-verify` is for testing only)
✅ **Log all integrations** for audit trail
✅ **Version control** integration scripts
✅ **Monitor integration status** with health checks
✅ **Set up alerts** for integration failures
✅ **Review permissions** for tool accounts regularly
✅ **Encrypt credentials** at rest and in transit

---

## Troubleshooting

### Splunk Connection Failed
```bash
# Verify HEC is enabled
curl -k https://splunk:8088/services/collector \
  -H "Authorization: Splunk $HEC_TOKEN" \
  -d '{"event":"test"}'

# Check Splunk logs
tail -f $SPLUNK_HOME/var/log/splunk/splunkd.log | grep HEC
```

### JIRA Authentication Error
```bash
# Verify token is valid
curl -u user:token https://jira.company.com/rest/api/3/myself

# Check project exists
curl -u user:token https://jira.company.com/rest/api/3/project/SEC
```

### Missing Dependencies
```bash
pip install requests dnspython paramiko pysnow slack
```

---

**Enterprise-grade integration ready!** ✅
