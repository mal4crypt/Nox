# NOX Framework - Quick Reference & Examples

## 🎯 What Each Tool Does - Quick Reference

| Tool | Task | Real Operation |
|------|------|----------------|
| **recon/subx** | Subdomain enumeration | Queries DNS servers for subdomains |
| **webpwn/sqlix** | SQL injection testing | Sends HTTP payloads, analyzes responses |
| **cred/sprayx** | Password spraying | Tests credentials with delay to prevent lockout |
| **netpwn/vlanx** | VLAN hopping | Sends DTP frames, tests VLAN traversal |
| **phish/campx** | Phishing campaigns | Connects to SMTP, sends emails, tracks opens |
| **c2/server** | C2 infrastructure | Runs HTTPS server, receives agent beacons |
| **pivot/sockx** | Network pivoting | Creates SOCKS proxy tunnels |
| **blue/memx** | Memory forensics | Parses memory dumps, identifies malware |
| **vuln/scanx** | Port scanning | Socket connections, CVE lookup |
| **watch/fimx** | File monitoring | Hash-based integrity monitoring |
| **comply/cisx** | Compliance checking | SSH/remote testing of CIS controls |
| **lab/vmx** | Lab environment | Creates VMs via hypervisor API |
| **report/renderx** | Report generation | Aggregates findings, renders PDF/HTML |

---

## 💻 Real Execution Examples

### RECONNAISSANCE PHASE
```bash
# 1. Discover subdomains via DNS
python3 nox recon subx --domain example.com --wordlist subdomains.txt --confirm-legal

# 2. Scan for open ports and services
python3 nox vuln scanx --target 93.184.216.34 --ports 1-10000 --vuln-check --confirm-legal

# 3. Test for SQL injection vulnerabilities
python3 nox webpwn sqlix --url "http://93.184.216.34/app.php?id=" --method GET --enum-dbs --confirm-legal
```

### EXPLOITATION PHASE
```bash
# 1. Spray credentials against domain
python3 nox cred sprayx --domain CONTOSO --users users.txt --password "Winter2025" --service ldap --threads 5 --delay 2 --confirm-legal

# 2. Test VLAN hopping
python3 nox netpwn vlanx --interface eth0 --method dtp --list-vlans --confirm-legal

# 3. Launch C2 server infrastructure
python3 nox c2/server --listen 0.0.0.0:8443 --profile https --cert cert.pem --key key.pem --operator operator1 --confirm-legal
```

### POST-EXPLOITATION PHASE
```bash
# 1. Create SOCKS proxy for pivoting
python3 nox pivot/sockx --listen 127.0.0.1:1080 --target 192.168.1.1 --user pivotuser --key id_rsa --version 5 --confirm-legal

# 2. Setup phishing infrastructure
python3 nox phish/campx --name campaign1 --targets targets.csv --template phish.html --smtp-server smtp.gmail.com --send --confirm-legal

# 3. Analyze memory for artifacts
python3 nox blue/memx --dump memory.dmp --enum-processes --find-strings --confirm-legal
```

### FORENSICS & DEFENSE
```bash
# 1. Monitor system for changes
python3 nox watch/fimx --path /etc --recursive --baseline baseline.json --watch --interval 60 --confirm-legal

# 2. Check CIS compliance
python3 nox comply/cisx --target 192.168.1.50 --os linux --benchmark 1 --remediate --dry-run --confirm-legal

# 3. Analyze system for vulnerabilities
python3 nox vuln/scanx --target 192.168.1.100 --scan-type thorough --vuln-check --confirm-legal
```

### REPORTING
```bash
# Generate professional penetration test report
python3 nox report/renderx \
  --findings findings.json \
  --template technical \
  --title "Penetration Test Report" \
  --client "ACME Corporation" \
  --date "2026-02-24" \
  --include-evidence \
  --include-remediation \
  --format pdf \
  --out-file pentest_report.pdf \
  --confirm-legal

# Alternative: HTML report
python3 nox report/renderx \
  --findings findings.json \
  --template executive \
  --title "Executive Summary" \
  --format html \
  --out-file executive_summary.html \
  --confirm-legal
```

---

## 🔧 Lab Setup Example

```bash
# Create isolated pentest lab with 3 VMs
python3 nox lab/vmx \
  --action create \
  --name pentest-lab \
  --template kali-linux-2024 \
  --count 3 \
  --memory 4096 \
  --cpus 4 \
  --disk 50gb \
  --hypervisor kvm \
  --confirm-legal

# Start the lab
python3 nox lab/vmx --action start --name pentest-lab --confirm-legal

# List active VMs
python3 nox lab/vmx --action list --confirm-legal

# Clean up after testing
python3 nox lab/vmx --action destroy --name pentest-lab --confirm-legal
```

---

## 📊 Output Examples

### vuln/scanx Output
```json
{
  "target": "192.168.1.1",
  "scan_type": "standard",
  "open_ports": [
    "22/tcp",
    "80/tcp",
    "443/tcp",
    "3306/tcp"
  ],
  "services": {
    "22/tcp": "SSH",
    "80/tcp": "HTTP",
    "443/tcp": "HTTPS",
    "3306/tcp": "MySQL"
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2021-36221",
      "severity": "High",
      "service": "OpenSSH"
    },
    {
      "cve": "CVE-2021-41773",
      "severity": "Critical",
      "service": "Apache"
    }
  ]
}
```

### cred/sprayx Output
```
[*] Starting password spray against: CONTOSO
[*] Spraying 25 accounts with password: Win***
[*] Service: LDAP
[*] Delay: 2s between attempts, 5 threads

[+] VALID: CONTOSO\admin
  [-] Invalid: user1
  [-] Invalid: user2
[+] VALID: CONTOSO\service_account

[+] Spray complete
  Valid accounts: 2
  Invalid accounts: 23
  Total attempts: 25
```

### blue/memx Output
```
[*] Analyzing memory dump: memory.dmp
[*] Volatility Profile: Win7SP1x64

Process Tree:
  PID    Name              Suspicious
  4      System            No
  784    explorer.exe      YES (injected DLL)
  1024   svchost.exe       No
  2048   malware.exe       YES

Injected DLLs Found:
  - explorer.exe: [malicious.dll]
  - svchost.exe: [rootkit.sys]

Suspicious Strings:
  "cmd.exe /c powershell -enc..."
  "C:\Windows\Temp\payload.exe"
```

---

## 🚀 Integrated Workflows

### Full Penetration Test Workflow
```bash
#!/bin/bash
# Complete pentest workflow

TARGET="example.com"
OUTPUT_DIR="./results"

# Phase 1: Reconnaissance
echo "[*] Phase 1: Reconnaissance"
python3 nox recon subx --domain $TARGET --confirm-legal --out-file "$OUTPUT_DIR/subdomains.json"

# Phase 2: Scanning
echo "[*] Phase 2: Vulnerability Scanning"
for subdomain in $(cat $OUTPUT_DIR/subdomains.json | grep -o '"[^"]*\.[^"]*"'); do
  python3 nox vuln scanx --target $subdomain --vuln-check --confirm-legal --out-file "$OUTPUT_DIR/scan_${subdomain}.json"
done

# Phase 3: Testing
echo "[*] Phase 3: Exploitation Testing"
python3 nox webpwn sqlix --url "http://$TARGET/app.php?id=" --enum-dbs --confirm-legal --out-file "$OUTPUT_DIR/sqli.json"
python3 nox cred sprayx --domain $TARGET --users users.txt --password "Test123" --confirm-legal --out-file "$OUTPUT_DIR/credentials.json"

# Phase 4: Reporting
echo "[*] Phase 4: Report Generation"
python3 nox report renderx \
  --findings "$OUTPUT_DIR/sqli.json" \
  --template technical \
  --title "Penetration Test - $TARGET" \
  --client "Client Inc" \
  --format pdf \
  --out-file "$OUTPUT_DIR/pentest_report.pdf" \
  --confirm-legal

echo "[+] Penetration test complete. Results in $OUTPUT_DIR/"
```

---

## 📋 Common Use Cases

### Use Case 1: Quick Security Assessment
```bash
# Scan target for vulnerabilities
python3 nox vuln scanx --target 192.168.1.1 --scan-type fast --confirm-legal --out-file scan.json

# Check compliance
python3 nox comply cisx --target 192.168.1.1 --os linux --benchmark 1 --confirm-legal --out-file compliance.json

# Generate report
python3 nox report renderx --findings scan.json --format html --out-file assessment.html --confirm-legal
```

### Use Case 2: Web Application Testing
```bash
# Test for SQL injection
python3 nox webpwn sqlix --url "http://target.com/search.php?q=" --method GET --enum-dbs --confirm-legal

# Password spray authentication
python3 nox cred sprayx --domain DOMAIN --users users.txt --password "Password123" --service ldap --confirm-legal

# Generate findings report
python3 nox report renderx --findings findings.json --template technical --format pdf --out-file report.pdf --confirm-legal
```

### Use Case 3: Post-Breach Analysis
```bash
# Analyze memory dump for malware
python3 nox blue memx --dump memory.dmp --enum-processes --find-strings --confirm-legal

# Check system compliance
python3 nox comply cisx --target compromised.host --os linux --benchmark 1 --confirm-legal

# Monitor file changes
python3 nox watch fimx --path /etc --baseline baseline.json --check current.json --confirm-legal
```

### Use Case 4: Authorized Red Team Operation
```bash
# Setup lab environment
python3 nox lab vmx --action create --name redteam --template kali-linux --count 5 --memory 4096 --confirm-legal

# Launch C2 infrastructure
python3 nox c2 server --listen 0.0.0.0:8443 --profile https --cert cert.pem --key key.pem --confirm-legal

# Setup lateral movement proxy
python3 nox pivot sockx --listen 127.0.0.1:1080 --target internal.network --user pivotuser --confirm-legal

# Coordinate phishing campaign
python3 nox phish campx --name campaign1 --targets targets.csv --template phish.html --confirm-legal
```

---

## ⚙️ Advanced Options

### Custom Wordlists
```bash
# Use custom wordlist for subdomain enumeration
python3 nox recon subx --domain example.com --wordlist my_subdomains.txt --confirm-legal

# Custom user list for password spray
python3 nox cred sprayx --domain CONTOSO --users my_users.txt --password "Test123" --confirm-legal
```

### Multi-Format Output
```bash
# Export as JSON (default)
python3 nox vuln scanx --target 192.168.1.1 --output json --out-file results.json --confirm-legal

# Export as CSV
python3 nox vuln scanx --target 192.168.1.1 --output csv --out-file results.csv --confirm-legal

# Export as text
python3 nox vuln scanx --target 192.168.1.1 --output txt --out-file results.txt --confirm-legal
```

### Parallel Operations
```bash
# Run multiple scans in parallel
for ip in 192.168.1.{1..10}; do
  python3 nox vuln scanx --target $ip --confirm-legal --out-file "scan_${ip}.json" &
done
wait
```

---

## 🔐 Security & Legal

**All tools require `--confirm-legal` flag:**
- Enforces authorization confirmation
- Requires explicit user acknowledgment
- Prevents accidental misuse
- Creates audit logs

**Unauthorized use is illegal.** Use only on systems you own or have explicit written permission to test.

---

**NOX Framework v2.0 - Professional Security Operations Toolkit**
February 24, 2026
