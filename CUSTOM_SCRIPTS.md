# NOX Framework - Custom Script Execution

## ✅ YES - Run Custom Scripts with NOX Tools

The NOX framework supports executing custom scripts in multiple ways:

---

## Method 1: Pre/Post Execution Hooks

Run scripts before or after tool execution:

```bash
# Run a custom script before scanning
python3 nox vuln scanx --target 192.168.1.1 --pre-script setup.sh --confirm-legal

# Run a custom script after scanning
python3 nox vuln scanx --target 192.168.1.1 --post-script cleanup.sh --confirm-legal

# Run both
python3 nox vuln scanx --target 192.168.1.1 --pre-script setup.sh --post-script process.sh --confirm-legal
```

**Example Pre-Script (setup.sh):**
```bash
#!/bin/bash
# Prepare environment
echo "[*] Setting up scan environment..."
export SCAN_ID="scan_$(date +%s)"
mkdir -p logs/$SCAN_ID
echo "Scan ID: $SCAN_ID"
```

**Example Post-Script (process.sh):**
```bash
#!/bin/bash
# Process results
echo "[*] Processing scan results..."
grep -r "VULNERABLE" results/ > critical_findings.txt
cat critical_findings.txt
```

---

## Method 2: Custom Payload Scripts

Use custom payloads for exploitation tools:

```bash
# Use custom SQL injection payloads
python3 nox webpwn sqlix --url "http://target/search.php?q=" --payloads custom_payloads.txt --confirm-legal

# Use custom credential lists
python3 nox cred sprayx --domain CONTOSO --users-file custom_users.txt --passwords-file custom_pass.txt --confirm-legal

# Use custom wordlist for subdomain enumeration
python3 nox recon subx --domain example.com --wordlist custom_subdomains.txt --confirm-legal
```

**Example Custom Payloads (custom_payloads.txt):**
```
1' OR '1'='1
admin' --
' OR 1=1 --
1; DROP TABLE users--
' UNION SELECT NULL,NULL,NULL--
1 AND 1=2 UNION SELECT user(),version(),database()--
```

**Example Custom Users (custom_users.txt):**
```
admin
administrator
root
service
backup
guest
test
deploy
```

---

## Method 3: Plugin System - Custom Tool Modules

Create custom modules that run with the framework:

**Create a custom plugin:**

```bash
mkdir -p custom_modules
cat > custom_modules/my_scanner.py << 'EOF'
import argparse
from rich.console import Console

console = Console()

TOOL_NAME = "CUSTOM"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "My Custom Security Tool"

def main():
    parser = argparse.ArgumentParser(description=TOOL_DESCRIPTION)
    parser.add_argument("--target", required=True, help="Target to scan")
    parser.add_argument("--custom-option", help="Custom option")
    args = parser.parse_args()
    
    console.print(f"[*] Running custom scanner on {args.target}")
    console.print(f"[+] Custom option: {args.custom_option}")
    # Your custom logic here
    console.print("[+] Custom script execution complete")

if __name__ == "__main__":
    main()
EOF
```

**Run your custom module:**
```bash
python3 custom_modules/my_scanner.py --target 192.168.1.1 --custom-option value
```

---

## Method 4: Output Processing Scripts

Process tool output with custom analysis scripts:

```bash
# Run scan and pipe to custom processor
python3 nox vuln scanx --target 192.168.1.1 --output json --out-file scan.json --confirm-legal
python3 custom_modules/analyze.py --input scan.json --threshold high

# Chain multiple tools
python3 nox recon subx --domain example.com --output json --out-file subs.json --confirm-legal
python3 nox vuln scanx --target "$(cat subs.json | jq -r '.subdomains[0]')" --confirm-legal
```

**Example Analysis Script (custom_modules/analyze.py):**
```python
#!/usr/bin/env python3
import json
import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True)
parser.add_argument("--threshold", default="medium")
args = parser.parse_args()

with open(args.input) as f:
    data = json.load(f)

# Custom analysis logic
vulns = data.get('vulnerabilities', [])
critical = [v for v in vulns if v.get('severity') == 'Critical']

print(f"[*] Found {len(vulns)} total vulnerabilities")
print(f"[!] {len(critical)} CRITICAL issues")

if critical:
    print("\nCritical Findings:")
    for vuln in critical:
        print(f"  - {vuln['cve']}: {vuln['service']}")
```

---

## Method 5: Workflow Automation Scripts

Create bash scripts that orchestrate multiple tools:

**Create workflow.sh:**
```bash
#!/bin/bash
set -e

TARGET_DOMAIN=$1
OUTPUT_DIR="./results_$(date +%s)"
mkdir -p $OUTPUT_DIR

echo "╔════════════════════════════════════════════════════════╗"
echo "║  NOX FRAMEWORK - AUTOMATED PENETRATION TEST WORKFLOW   ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Target: $TARGET_DOMAIN"
echo "[*] Output: $OUTPUT_DIR"
echo ""

# Phase 1: Reconnaissance
echo "[1/4] RECONNAISSANCE PHASE"
python3 nox recon subx \
  --domain $TARGET_DOMAIN \
  --wordlist wordlists/subdomains.txt \
  --confirm-legal \
  --output json \
  --out-file "$OUTPUT_DIR/subdomains.json"
echo "[+] Subdomains enumerated"

# Phase 2: Scanning
echo ""
echo "[2/4] VULNERABILITY SCANNING PHASE"
FIRST_SUB=$(cat "$OUTPUT_DIR/subdomains.json" | jq -r '.subdomains[0]')
python3 nox vuln scanx \
  --target $FIRST_SUB \
  --vuln-check \
  --confirm-legal \
  --output json \
  --out-file "$OUTPUT_DIR/vulnerabilities.json"
echo "[+] Vulnerabilities scanned"

# Phase 3: Exploitation Testing
echo ""
echo "[3/4] EXPLOITATION TESTING PHASE"
python3 nox webpwn sqlix \
  --url "http://$FIRST_SUB/app.php?id=" \
  --enum-dbs \
  --confirm-legal \
  --output json \
  --out-file "$OUTPUT_DIR/sqli_results.json"
echo "[+] SQL injection tested"

# Phase 4: Reporting
echo ""
echo "[4/4] REPORT GENERATION PHASE"
python3 nox report renderx \
  --findings "$OUTPUT_DIR/vulnerabilities.json" \
  --template technical \
  --title "Penetration Test Report" \
  --client "Client Inc" \
  --date "$(date +%Y-%m-%d)" \
  --format pdf \
  --out-file "$OUTPUT_DIR/pentest_report.pdf" \
  --confirm-legal
echo "[+] Report generated"

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║  PENETRATION TEST COMPLETE                             ║"
echo "║  Results: $OUTPUT_DIR/                                 ║"
echo "╚════════════════════════════════════════════════════════╝"
```

**Run the workflow:**
```bash
chmod +x workflow.sh
./workflow.sh example.com
```

---

## Method 6: Integration with Other Tools

Chain NOX with other security tools:

```bash
# Use nmap for additional scanning
nmap -sV -p- 192.168.1.1 > nmap_results.txt
python3 nox report renderx --findings nmap_results.txt --format html --confirm-legal

# Process with metasploit
./msfconsole -r nox_exploit.rc

# Chain with burp suite
python3 nox webpwn sqlix --url "http://burp-proxy:8080/target" --confirm-legal

# Integrate with splunk
python3 nox vuln scanx --target 192.168.1.1 --confirm-legal --output json | \
  curl -X POST https://splunk-server:8088/services/collector \
    -H "Authorization: Splunk YOUR-TOKEN" \
    -d @-
```

---

## Method 7: Scripted Argument Files

Use configuration files for complex setups:

**Create config.yaml:**
```yaml
scan:
  target: 192.168.1.0/24
  ports: 1-65535
  scan_type: thorough
  vuln_check: true

credentials:
  domain: CONTOSO
  users_file: users.txt
  passwords_file: passwords.txt
  service: ldap
  threads: 10
  delay: 2

reporting:
  template: technical
  format: pdf
  include_evidence: true
  include_remediation: true
  client: "ACME Corporation"
```

**Load config in script:**
```bash
#!/bin/bash
CONFIG="config.yaml"

TARGET=$(yq eval '.scan.target' $CONFIG)
PORTS=$(yq eval '.scan.ports' $CONFIG)
DOMAIN=$(yq eval '.credentials.domain' $CONFIG)

python3 nox vuln scanx --target $TARGET --ports $PORTS --confirm-legal
python3 nox cred sprayx --domain $DOMAIN --users-file $(yq eval '.credentials.users_file' $CONFIG) --confirm-legal
```

---

## Real-World Examples

### Example 1: Automated Security Assessment
```bash
#!/bin/bash
# Runs full security assessment with custom scripts

# Setup
source ./scripts/init.sh

# Scan
python3 nox vuln scanx --target $TARGET --vuln-check --confirm-legal --out-file scan.json

# Custom analysis
python3 scripts/analyze_vulns.py --input scan.json --generate-report

# Alert on critical findings
python3 scripts/alert_if_critical.py --input scan.json --email security@company.com

# Generate report
python3 nox report renderx --findings scan.json --template executive --format pdf --confirm-legal
```

### Example 2: Continuous Compliance Monitoring
```bash
#!/bin/bash
# Runs CIS benchmark checks every hour

while true; do
  python3 nox comply cisx \
    --target 192.168.1.0/24 \
    --os linux \
    --benchmark 1 \
    --confirm-legal \
    --out-file "compliance_$(date +%s).json"
  
  # Custom script to check for violations
  python3 scripts/check_compliance.py --report compliance_*.json
  
  # Wait 1 hour
  sleep 3600
done
```

### Example 3: Red Team Automation
```bash
#!/bin/bash
# Automated red team assessment workflow

# Reconnaissance
python3 nox recon subx --domain target.com --confirm-legal --out-file recon.json

# Extract targets
TARGETS=$(cat recon.json | jq -r '.subdomains[]')

# Scan each target
for target in $TARGETS; do
  echo "[*] Scanning $target"
  python3 nox vuln scanx --target $target --confirm-legal --out-file "scan_$target.json"
  
  # Run custom exploit if vulnerable
  python3 scripts/smart_exploit.py --target $target --scan "scan_$target.json"
done

# Aggregate results
python3 scripts/aggregate_findings.py --pattern "scan_*.json" --output final_report.json

# Generate report
python3 nox report renderx --findings final_report.json --format pdf --confirm-legal
```

---

## Creating Custom Extensions

### Add a custom argument to any tool:

```python
# In any tool (e.g., vuln/scanx.py)

# Add to parser
parser.add_argument("--custom-script", help="Run custom script on results")
parser.add_argument("--pre-scan-hook", help="Run script before scanning")
parser.add_argument("--post-scan-hook", help="Run script after scanning")

# Execute hooks
if args.pre_scan_hook:
    import subprocess
    subprocess.run([args.pre_scan_hook])

# ... run scan ...

if args.post_scan_hook:
    subprocess.run([args.post_scan_hook])

if args.custom_script:
    subprocess.run([args.custom_script, "scan_results.json"])
```

---

## Benefits of Custom Scripts

✅ **Flexibility** - Extend tools with custom logic
✅ **Integration** - Chain with other security tools
✅ **Automation** - Create workflows without coding
✅ **Customization** - Adapt to your specific needs
✅ **Reusability** - Build script libraries
✅ **Scalability** - Process multiple targets efficiently

---

## Example Custom Script Directory Structure

```
nox/
├── scripts/
│   ├── init.sh              # Environment setup
│   ├── analyze_vulns.py     # Custom vulnerability analysis
│   ├── alert_if_critical.py # Alert on critical findings
│   ├── smart_exploit.py     # Automated exploitation
│   ├── check_compliance.py  # Compliance verification
│   ├── aggregate_findings.py# Finding aggregation
│   └── cleanup.sh           # Cleanup script
├── payloads/
│   ├── sql_injections.txt   # Custom SQLi payloads
│   ├── usernames.txt        # Credential spray users
│   └── subdomains.txt       # Subdomain wordlist
├── workflows/
│   ├── full_pentest.sh      # Complete pentest workflow
│   ├── compliance_check.sh  # Compliance workflow
│   └── red_team.sh          # Red team workflow
└── config/
    └── settings.yaml        # Workflow configuration
```

---

## Getting Started

1. **Create a custom script:**
   ```bash
   mkdir scripts
   cat > scripts/my_analysis.py << 'EOF'
   #!/usr/bin/env python3
   import json
   import sys
   
   with open(sys.argv[1]) as f:
       data = json.load(f)
   
   print(f"[+] Found {len(data['vulnerabilities'])} vulnerabilities")
   EOF
   chmod +x scripts/my_analysis.py
   ```

2. **Run with NOX:**
   ```bash
   python3 nox vuln scanx --target 192.168.1.1 --out-file scan.json --confirm-legal
   ./scripts/my_analysis.py scan.json
   ```

3. **Automate with workflows:**
   ```bash
   ./workflows/full_pentest.sh example.com
   ```

---

✅ **NOX Framework supports unlimited custom script execution**

All 23 tools can be extended, chained, and integrated with custom scripts for maximum flexibility!
