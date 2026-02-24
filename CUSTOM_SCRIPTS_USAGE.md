# NOX Custom Scripts - Complete Usage Guide

## ✅ Run Custom Scripts with NOX Tools

The NOX framework includes **ready-to-use custom scripts** that extend tool functionality.

---

## Quick Start

### 1. Run Full Automated Penetration Test
```bash
chmod +x scripts/full_pentest_workflow.sh
./scripts/full_pentest_workflow.sh example.com
```

**What it does:**
- ✅ Enumerates subdomains via DNS
- ✅ Scans for open ports & vulnerabilities
- ✅ Tests for SQL injection
- ✅ Analyzes findings automatically
- ✅ Generates comprehensive PDF report

**Output:**
```
pentest_results_1708850400/
├── subdomains.json
├── scan_1.json
├── sqli_results.json
├── pentest_report_example.com.pdf
└── logs/
    ├── recon.log
    ├── scanning.log
    ├── exploitation.log
    └── reporting.log
```

---

## Included Custom Scripts

### 1. analyze_vulnerabilities.py
**Analyze and categorize scan results**

```bash
# Run NOX scan
python3 nox vuln scanx --target 192.168.1.1 --vuln-check --confirm-legal --out-file scan.json

# Analyze results
python3 scripts/analyze_vulnerabilities.py --input scan.json --generate-report
```

**Output:**
```
╔════════════════════════════════════════════════════════╗
║       NOX VULNERABILITY ANALYSIS REPORT                ║
╚════════════════════════════════════════════════════════╝

Target: 192.168.1.1
Total Findings: 7

[Critical] 1 findings (Risk: 5)
[High    ] 2 findings (Risk: 8)
[Medium  ] 4 findings (Risk: 12)

[TOTAL RISK SCORE: 25]

🔴 HIGH RISK - Address within 1 week

Analysis complete - 7 vulnerabilities analyzed
Report saved: scan_analysis.json
```

---

### 2. alert_if_critical.py
**Alert when critical vulnerabilities are found**

```bash
# Send email alert if critical issues found
python3 scripts/alert_if_critical.py --input scan.json --email admin@company.com

# Send Slack alert
python3 scripts/alert_if_critical.py --input scan.json --slack-webhook https://hooks.slack.com/...
```

**Features:**
- ✅ Detects critical vulnerabilities
- ✅ Sends email alerts
- ✅ Posts to Slack
- ✅ Triggers automation on critical findings
- ✅ Returns exit codes for CI/CD integration

---

### 3. aggregate_findings.py
**Combine results from multiple scans**

```bash
# Aggregate all scan results
python3 scripts/aggregate_findings.py --pattern "scan_*.json" --output combined.json

# Aggregate from directory
python3 scripts/aggregate_findings.py --dir ./results --output aggregated.json
```

**Output:**
```json
{
  "timestamp": "2026-02-24T10:30:00",
  "summary": {
    "total_targets": 5,
    "total_vulnerabilities": 23,
    "total_unique_ports": 12,
    "scan_files_processed": 5
  },
  "vulnerabilities_by_severity": {
    "Critical": 2,
    "High": 5,
    "Medium": 8,
    "Low": 8
  },
  "vulnerabilities_by_service": {
    "Apache": 3,
    "OpenSSH": 2,
    "MySQL": 5
  }
}
```

---

## Advanced Usage Examples

### Example 1: Automated Daily Security Assessment
```bash
#!/bin/bash
# Run daily security checks and alert if critical

TIMESTAMP=$(date +%Y%m%d)
OUTPUT_DIR="./daily_scans/$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

# Scan critical systems
for target in 192.168.1.100 192.168.1.101 192.168.1.102; do
  python3 nox vuln scanx \
    --target $target \
    --vuln-check \
    --confirm-legal \
    --out-file "$OUTPUT_DIR/scan_$target.json"
done

# Aggregate results
python3 scripts/aggregate_findings.py \
  --pattern "$OUTPUT_DIR/scan_*.json" \
  --output "$OUTPUT_DIR/summary.json"

# Alert on critical findings
python3 scripts/alert_if_critical.py \
  --input "$OUTPUT_DIR/summary.json" \
  --email security@company.com

# Generate report
python3 nox report renderx \
  --findings "$OUTPUT_DIR/summary.json" \
  --template executive \
  --format pdf \
  --out-file "$OUTPUT_DIR/daily_report.pdf" \
  --confirm-legal
```

### Example 2: Continuous Compliance Monitoring
```bash
#!/bin/bash
# Check compliance hourly and alert on violations

while true; do
  TIMESTAMP=$(date +%s)
  OUTPUT="compliance_$TIMESTAMP.json"
  
  # Check CIS compliance
  python3 nox comply cisx \
    --target 192.168.1.0/24 \
    --os linux \
    --benchmark 1 \
    --confirm-legal \
    --out-file "$OUTPUT"
  
  # Analyze results
  python3 scripts/analyze_vulnerabilities.py --input "$OUTPUT"
  
  # Alert if compliance score drops below 75%
  SCORE=$(jq '.compliance_score' "$OUTPUT")
  if (( $(echo "$SCORE < 75" | bc -l) )); then
    python3 scripts/alert_if_critical.py \
      --input "$OUTPUT" \
      --slack-webhook https://hooks.slack.com/...
  fi
  
  # Wait 1 hour
  sleep 3600
done
```

### Example 3: Red Team Assessment Workflow
```bash
#!/bin/bash
# Complete red team exercise workflow

TARGET_DOMAIN=$1
WORKFLOW_ID=$(date +%s)
OUTPUT_DIR="./redteam_$WORKFLOW_ID"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting red team assessment: $TARGET_DOMAIN"

# Phase 1: Reconnaissance
echo "[1] Reconnaissance..."
./scripts/full_pentest_workflow.sh "$TARGET_DOMAIN"

# Phase 2: Extract and analyze targets
echo "[2] Analyzing reconnaissance data..."
python3 scripts/aggregate_findings.py \
  --dir ./pentest_results_* \
  --output "$OUTPUT_DIR/all_findings.json"

# Phase 3: Custom exploitation
echo "[3] Running custom exploitation scripts..."
python3 custom_exploits/exploit_vulns.py \
  --findings "$OUTPUT_DIR/all_findings.json" \
  --output "$OUTPUT_DIR/exploitation_results.json"

# Phase 4: Final reporting
echo "[4] Generating final report..."
python3 nox report renderx \
  --findings "$OUTPUT_DIR/all_findings.json" \
  --template technical \
  --title "Red Team Assessment" \
  --client "Target Organization" \
  --format pdf \
  --out-file "$OUTPUT_DIR/redteam_report.pdf" \
  --confirm-legal

echo "[+] Assessment complete: $OUTPUT_DIR/"
```

---

## Integration with Other Tools

### Chain with Metasploit
```bash
# Generate NOX findings
python3 nox vuln scanx --target 192.168.1.1 --out-file scan.json --confirm-legal

# Process with Metasploit
python3 scripts/nox_to_metasploit.py --findings scan.json --output metasploit.rc
msfconsole -r metasploit.rc
```

### Send to Splunk
```bash
# Run scan
python3 nox vuln scanx --target 192.168.1.1 --output json --out-file scan.json --confirm-legal

# Forward to Splunk
cat scan.json | curl -X POST \
  https://splunk-server:8088/services/collector \
  -H "Authorization: Splunk YOUR-TOKEN" \
  -d @-
```

### Create Jira Tickets
```bash
# Run scan
python3 nox vuln scanx --target 192.168.1.1 --out-file scan.json --confirm-legal

# Create tickets
python3 scripts/create_jira_tickets.py \
  --findings scan.json \
  --project SEC \
  --assignee security-team
```

---

## Creating Your Own Custom Scripts

### Template: Basic Custom Script
```python
#!/usr/bin/env python3
"""
Custom NOX script template
"""

import json
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="My custom NOX script")
    parser.add_argument("--input", required=True, help="NOX results JSON file")
    parser.add_argument("--output", help="Output file")
    
    args = parser.parse_args()
    
    # Load NOX results
    with open(args.input) as f:
        data = json.load(f)
    
    # Process data
    vulnerabilities = data.get('vulnerabilities', [])
    
    print(f"[*] Processing {len(vulnerabilities)} vulnerabilities...")
    
    # Your custom logic here
    
    # Save results if specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
```

### Template: Bash Workflow Script
```bash
#!/bin/bash
# My custom NOX workflow

TARGET=$1
OUTPUT_DIR="./results_$(date +%s)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting custom workflow for $TARGET"

# Step 1: Reconnaissance
python3 nox recon subx --domain "$TARGET" --confirm-legal \
  --out-file "$OUTPUT_DIR/step1_recon.json"

# Step 2: Scanning
python3 nox vuln scanx --target "$TARGET" --confirm-legal \
  --out-file "$OUTPUT_DIR/step2_scan.json"

# Step 3: Custom analysis
python3 scripts/my_analysis.py --input "$OUTPUT_DIR/step2_scan.json" \
  --output "$OUTPUT_DIR/step3_analysis.json"

# Step 4: Reporting
python3 nox report renderx --findings "$OUTPUT_DIR/step3_analysis.json" \
  --format pdf --out-file "$OUTPUT_DIR/report.pdf" --confirm-legal

echo "[+] Workflow complete: $OUTPUT_DIR/"
```

---

## Script Directory Structure

```
nox/
├── scripts/
│   ├── full_pentest_workflow.sh       # Complete automated pentest
│   ├── analyze_vulnerabilities.py     # Analyze scan results
│   ├── alert_if_critical.py           # Alert on critical findings
│   ├── aggregate_findings.py          # Combine multiple scans
│   ├── create_jira_tickets.py         # Create Jira issues (custom)
│   ├── send_to_splunk.py              # Forward to Splunk (custom)
│   └── nox_to_metasploit.py          # Convert to Metasploit (custom)
├── payloads/
│   ├── sql_injections.txt
│   ├── usernames.txt
│   └── subdomains.txt
└── workflows/
    ├── daily_assessment.sh
    ├── compliance_monitor.sh
    └── red_team.sh
```

---

## Common Patterns

### Pattern 1: Scan → Analyze → Alert
```bash
python3 nox vuln scanx --target 192.168.1.1 --out-file scan.json --confirm-legal
python3 scripts/analyze_vulnerabilities.py --input scan.json
python3 scripts/alert_if_critical.py --input scan.json --email admin@company.com
```

### Pattern 2: Multiple Scans → Aggregate → Report
```bash
for target in 192.168.1.{1..10}; do
  python3 nox vuln scanx --target $target --out-file "scan_$target.json" --confirm-legal
done
python3 scripts/aggregate_findings.py --pattern "scan_*.json" --output combined.json
python3 nox report renderx --findings combined.json --format pdf --confirm-legal
```

### Pattern 3: Continuous Monitoring
```bash
while true; do
  python3 nox comply cisx --target 192.168.1.0/24 --os linux --out-file compliance.json --confirm-legal
  python3 scripts/analyze_vulnerabilities.py --input compliance.json
  sleep 3600  # Check hourly
done
```

---

## Tips for Custom Scripts

✅ **Always expect JSON input** from NOX tools
✅ **Use `--output json`** flag when calling NOX tools
✅ **Handle errors gracefully** - check file existence
✅ **Add logging** - helps with debugging
✅ **Return proper exit codes** - for automation/CI-CD
✅ **Document your scripts** - help future users
✅ **Test on sample data** - before production use
✅ **Keep scripts modular** - easy to reuse parts

---

## Troubleshooting

### Script Not Found
```bash
# Make sure script is executable
chmod +x scripts/my_script.sh

# Use absolute or relative path
python3 ./scripts/analyze_vulnerabilities.py --input scan.json
```

### JSON Parse Error
```bash
# Verify JSON output from NOX
python3 nox vuln scanx --target 192.168.1.1 --output json --confirm-legal | python3 -m json.tool
```

### Permission Denied
```bash
# Make Python scripts executable
chmod +x scripts/*.py

# Or run with python3 explicitly
python3 scripts/analyze_vulnerabilities.py --input scan.json
```

---

**✅ NOX Framework supports unlimited custom script execution for maximum flexibility!**

All scripts included and ready to use. Extend as needed for your specific requirements.
