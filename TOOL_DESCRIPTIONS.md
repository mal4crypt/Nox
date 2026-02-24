# NOX Framework - Tool Descriptions & Usage

## Overview
Nox is a comprehensive security framework with 23 specialized tools across three domains:
- **Offensive** (7 tools): Reconnaissance, exploitation, social engineering
- **Defensive** (4 tools): Detection, forensics, compliance monitoring
- **Infrastructure** (2 tools): Lab management, report generation

---

## OFFENSIVE TOOLS (7)

### recon/subx - Subdomain Enumeration
**Purpose:** Discover subdomains for reconnaissance

**Arguments:**
```bash
nox recon subx --domain example.com [--wordlist list.txt] [--all] [--passive] [--threads 10]
```

**What it does:**
- Performs DNS lookups on common subdomains
- Can load custom wordlists for brute-force
- Passive mode uses WHOIS/DNS records only
- Returns: Found subdomains and their IPs
- Output: JSON, CSV, or TXT

**Example:**
```bash
python3 nox recon subx --domain example.com --confirm-legal --out-file results.json
```

---

### webpwn/sqlix - SQL Injection Testing
**Purpose:** Test web applications for SQL injection vulnerabilities

**Arguments:**
```bash
nox webpwn sqlix --url "http://target.com/page.php" [--parameter id] [--method POST] [--enum-dbs]
```

**What it does:**
- Sends SQL injection test payloads to target
- Tests basic, boolean-based, and time-based SQLi
- Can enumerate databases if vulnerable
- Detects vulnerable parameters
- Returns: Vulnerability status and findings

**Example:**
```bash
python3 nox webpwn sqlix --url "http://target.com/search.php?q=" --confirm-legal --method GET
```

---

### cred/sprayx - Password Spraying
**Purpose:** Test authentication with credential spraying attacks

**Arguments:**
```bash
nox cred sprayx --domain CONTOSO --users users.txt --password Pass123 [--service ldap]
```

**What it does:**
- Tests single password against multiple users
- Supports LDAP, SMB, Kerberos services
- Implements delay to avoid lockout
- Multi-threaded for efficiency
- Returns: Valid credentials found

**Example:**
```bash
python3 nox cred sprayx --domain CONTOSO --users admin,user,guest --password Winter2025 --confirm-legal
```

---

### netpwn/vlanx - VLAN Hopping
**Purpose:** Test network infrastructure for VLAN vulnerabilities

**Arguments:**
```bash
nox netpwn vlanx --interface eth0 [--target-vlan 100] [--method dtp] [--list-vlans]
```

**What it does:**
- Detects VLAN configuration
- Tests DTP (Dynamic Trunking Protocol) vulnerabilities
- Can perform VLAN hopping attacks
- Enumerates network segments
- Returns: VLAN info and exploitation results

**Example:**
```bash
python3 nox netpwn vlanx --interface eth0 --list-vlans --confirm-legal
```

---

### phish/campx - Phishing Campaign Management
**Purpose:** Create and manage phishing campaign infrastructure

**Arguments:**
```bash
nox phish campx --name "campaign1" --targets targets.csv --template phish.html --smtp-server smtp.server
```

**What it does:**
- Generates phishing email campaigns
- Manages target lists
- Customizable email templates
- SMTP configuration for sending
- Dry-run mode for testing
- Returns: Campaign status and metrics

**Example:**
```bash
python3 nox phish campx --name campaign1 --targets targets.csv --dry-run --confirm-legal
```

---

### c2/server - Command & Control Framework
**Purpose:** Deploy and manage C2 server infrastructure

**Arguments:**
```bash
nox c2 server --listen 0.0.0.0:8080 [--profile http] [--cert cert.pem] [--key key.pem]
```

**What it does:**
- Launches C2 server for agent communication
- Supports HTTP, HTTPS, DNS profiles
- Manages encrypted sessions with operators
- Logs all C2 activity and commands
- Returns: Server status and activity logs

**Example:**
```bash
python3 nox c2 server --listen 0.0.0.0:8443 --profile https --operator operator1 --confirm-legal
```

---

### pivot/sockx - SOCKS Proxy & Lateral Movement
**Purpose:** Create proxy tunnels for network pivoting

**Arguments:**
```bash
nox pivot sockx --listen 127.0.0.1:1080 --target internal.network [--version 5]
```

**What it does:**
- Establishes SOCKS proxy for tunneling
- Enables lateral movement in networks
- Supports SSH key/password authentication
- SOCKS4/SOCKS5 support
- Multi-threaded connections
- Returns: Connection logs and traffic metrics

**Example:**
```bash
python3 nox pivot sockx --listen 0.0.0.0:1080 --target 192.168.1.1 --confirm-legal
```

---

## DEFENSIVE TOOLS (4)

### blue/memx - Memory Forensics & Analysis
**Purpose:** Analyze memory dumps for malware and artifacts

**Arguments:**
```bash
nox blue memx --dump /path/to/memory.dmp [--pid 1234] [--enum-processes] [--find-strings]
```

**What it does:**
- Parses memory dumps for forensic analysis
- Enumerates running processes and their modules
- Searches for strings and artifacts
- Identifies suspicious activity patterns
- Compatible with Volatility profiles
- Returns: Process trees, DLLs, strings, artifacts

**Example:**
```bash
python3 nox blue memx --dump memory.dmp --enum-processes --confirm-legal --output json
```

---

### vuln/scanx - Vulnerability Scanner
**Purpose:** Scan systems for security vulnerabilities

**Arguments:**
```bash
nox vuln scanx --target 192.168.1.1 [--ports 1-1000] [--scan-type fast] [--service-detection]
```

**What it does:**
- Port scanning with service detection
- Vulnerability check against common CVEs
- OS fingerprinting
- Service version detection
- Three scan profiles: fast, standard, thorough
- Returns: Vulnerabilities and severity ratings

**Example:**
```bash
python3 nox vuln scanx --target 192.168.1.1 --scan-type standard --confirm-legal
```

---

### watch/fimx - File Integrity Monitoring
**Purpose:** Monitor file changes and detect tampering

**Arguments:**
```bash
nox watch fimx --path /etc --baseline baseline.json [--watch] [--interval 60]
```

**What it does:**
- Creates file integrity baselines using hashing
- Monitors directories for changes
- Alerts on file modifications/deletions/additions
- Multiple hash algorithms (MD5, SHA1, SHA256)
- Real-time or periodic monitoring
- Returns: Change logs and alerts

**Example:**
```bash
python3 nox watch fimx --path /etc --baseline baseline.json --hash-algo sha256 --confirm-legal
```

---

### comply/cisx - CIS Benchmark Compliance
**Purpose:** Assess system compliance with CIS benchmarks

**Arguments:**
```bash
nox comply cisx --target 192.168.1.1 --os linux [--benchmark 1] [--remediate] [--dry-run]
```

**What it does:**
- Evaluates systems against CIS benchmarks
- Tests Level 1 and Level 2 controls
- Generates compliance reports
- Provides remediation scripts
- Dry-run mode for testing changes
- Returns: Compliance score and remediation steps

**Example:**
```bash
python3 nox comply cisx --target 192.168.1.1 --os linux --benchmark 1 --confirm-legal
```

---

## INFRASTRUCTURE TOOLS (2)

### lab/vmx - Attack Lab Environment
**Purpose:** Create and manage isolated attack lab VMs

**Arguments:**
```bash
nox lab vmx --action create --name lab-vm --template kali-linux [--count 3] [--memory 4096] [--cpus 4]
```

**What it does:**
- Creates isolated lab environments quickly
- Manages VM templates (Kali, Windows, Ubuntu, etc.)
- Configures networking and resources
- Supports multiple hypervisors
- Bulk VM creation for testing
- Returns: VM status and configuration

**Example:**
```bash
python3 nox lab vmx --action create --name testlab --template ubuntu20 --count 1 --memory 2048 --confirm-legal
```

---

### report/renderx - Report Generation
**Purpose:** Aggregate findings and generate professional reports

**Arguments:**
```bash
nox report renderx --findings findings.json --title "Pentest Report" --client "ACME Corp" [--format pdf]
```

**What it does:**
- Aggregates findings from multiple tools
- Generates professional reports (PDF, HTML, DOCX)
- Customizable templates (executive, technical, compliance)
- Includes evidence and remediation steps
- Automatic date and client information
- Returns: Report files and metadata

**Example:**
```bash
python3 nox report renderx --findings findings.json --title "Security Assessment" --client "Example Inc" --format html --confirm-legal
```

---

## INTEGRATED LEGACY TOOLS (10)

### frizz/modx - Protocol Fuzzing
Tests protocol implementations for vulnerabilities

### rift/s3scan - Cloud Bucket Scanner
Scans AWS S3 buckets for misconfigurations

### kerb/tixr - Kerberos/AD Attacks
Tests Active Directory and Kerberos implementations

### spekt/intel - OSINT Automation
Automated open-source intelligence gathering

### shade/cloak - Evasion & AV Bypass
Tests evasion techniques against security controls

### mobi/droid - Mobile Pentesting
Android app security testing and analysis

### firm/flash - Hardware Security
Firmware analysis and hardware hacking

### wraith/recon - Post-Exploitation
Post-exploitation reconnaissance and lateral movement

### forge/hunt - Threat Hunting
Threat hunting and log analysis for detection

### apix/rest - API Security
REST API security testing and fuzzing

---

## COMMON ARGUMENTS (ALL TOOLS)

```
--confirm-legal        Confirm authorized use (required for security tools)
--output {json,csv,txt}  Output format (default: json)
--out-file FILE        Save results to file
--help                 Show detailed help for the tool
```

---

## INSTALLATION & SETUP

```bash
# Install dependencies
pip install -r requirements.txt

# Make launcher executable
chmod +x nox

# Test installation
python3 nox --help
```

---

## EXECUTION EXAMPLES

**Reconnaissance workflow:**
```bash
# Discover subdomains
python3 nox recon subx --domain example.com --confirm-legal --out-file subs.json

# Scan discovered hosts
python3 nox vuln scanx --target 192.168.1.1 --confirm-legal --out-file vuln.json

# Generate report
python3 nox report renderx --findings vuln.json --title "Assessment" --format pdf --confirm-legal
```

**Post-exploitation workflow:**
```bash
# Analyze memory dump
python3 nox blue memx --dump memory.dmp --enum-processes --confirm-legal

# Check compliance
python3 nox comply cisx --target 192.168.1.1 --os linux --confirm-legal

# Generate findings report
python3 nox report renderx --findings findings.json --format html --confirm-legal
```

---

## SECURITY & LEGAL

⚠️ **IMPORTANT**: All tools require `--confirm-legal` to enforce:
- Legal authorization verification
- Ethical use acknowledgment
- Incident logging and audit trails

Unauthorized use is illegal. Use only on systems you own or have explicit written permission to test.

---

**Framework Version:** 2.0  
**Last Updated:** February 24, 2026  
**License:** MIT (Open Source)  
**Organization:** Raven-Security Community
