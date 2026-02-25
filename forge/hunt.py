import sys
import argparse
import os
import re
import getpass
from rich.console import Console
from rich.table import Table
from utils.banner import print_nox_banner
from utils.logger import setup_logger, audit_log
from utils.formatter import format_output
import datetime

console = Console()
logger = setup_logger("forge_hunt")

# --- Identity ---
TOOL_NAME = "FORGE"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Threat Hunting & Detection Suite - Log Analysis"

# --- Banner Config ---
BORDER = "orange3"
NAME_COLOR = "bold orange3"
FILL_COLOR = "orange1"
TAG_COLOR = "wheat1"
FCHAR = "◈"

ART_LINES = [
    "    ███████╗██████╗ ██████╗  ██████╗ ███████╗",
    "    ██╔════╝██╔══██╗██╔══██╗██╔════╝ ██╔════╝",
    "    █████╗  ██║  ██║██████╔╝██║  ███╗█████╗  ",
    "    ██╔══╝  ██║  ██║██╔══██╗██║   ██║██╔══╝  ",
    "    ██║     ██████╔╝██║  ██║╚██████╔╝███████╗",
    "    ╚═╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox.py forge hunt"
    )
    
    # Input
    parser.add_argument("--file", required=True, help="Path to the log file to analyze")
    
    # Hunting Options
    parser.add_argument("--suspicious", action="store_true", help="Search for suspicious shell commands/keywords")
    parser.add_argument("--ips", action="store_true", help="Extract and analyze IP address frequencies")
    parser.add_argument("--regex", help="Custom regex pattern to hunt for")
    parser.add_argument("--all", action="store_true", help="Run all hunting tasks")
    
    # Standards
    parser.add_argument("--output", choices=["json", "csv", "txt"], default="json", help="Output format")
    parser.add_argument("--confirm-legal", action="store_true", help="Confirm authorized use")
    
    args = parser.parse_args()

    # Step 1: Banner
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)

    # Step 2: Legal Check
    if not args.confirm_legal:
        console.print("[bold yellow]⚠ Legal Confirmation Required[/bold yellow]")
        confirm = input("Confirm you have authorization to test this target (yes/no): ").lower()
        if confirm != 'yes':
            console.print("[bold red]Aborting. Authorized use only.[/bold red]")
            sys.exit(1)

    # Step 3: Run Logic
    run_hunt(args)

def run_hunt(args):
    """
    Core logic for comprehensive threat hunting in logs with advanced detection.
    """
    input_file = args.file
    if not os.path.exists(input_file):
        console.print(f"[bold red]Error:[/bold red] Log file {input_file} not found.")
        return

    console.print(f"[*] Hunting in: [bold white]{input_file}[/bold white]...")
    logger.info(f"Forge Hunt started: file={input_file}")
    
    results = {
        "file": input_file,
        "file_size_bytes": os.path.getsize(input_file),
        "total_lines": 0,
        "suspicious_matches": [],
        "attack_patterns": {
            "command_injection": [],
            "credential_exposure": [],
            "malware_indicators": [],
            "exfiltration": [],
            "persistence": [],
            "privilege_escalation": []
        },
        "ip_frequencies": {},
        "ip_risk_assessment": {},
        "user_activity": {},
        "custom_matches": [],
        "severity_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "hunting_statistics": {},
        "timestamp": datetime.datetime.now().isoformat()
    }

    # Comprehensive suspicious patterns with severity
    suspicious_patterns = {
        "command_injection": [
            {"pattern": r"base64", "severity": "High", "description": "Base64 encoded command/payload"},
            {"pattern": r"nc -e|ncat -e|bash -i", "severity": "Critical", "description": "Reverse shell attempt"},
            {"pattern": r"python -c|perl -e", "severity": "High", "description": "Inline script execution"},
            {"pattern": r"eval\(|exec\(", "severity": "Critical", "description": "Dynamic code execution"},
            {"pattern": r"\$\(\s*", "severity": "High", "description": "Command substitution"},
            {"pattern": r">\s*/dev/tcp", "severity": "Critical", "description": "Network redirection"},
        ],
        "credential_exposure": [
            {"pattern": r"password\s*[=:|]\s*\S+", "severity": "Critical", "description": "Hardcoded password"},
            {"pattern": r"api_key\s*[=:|]\s*\S+", "severity": "Critical", "description": "API key exposure"},
            {"pattern": r"secret\s*[=:|]\s*\S+", "severity": "High", "description": "Secret exposure"},
            {"pattern": r"token\s*[=:|]\s*\S+", "severity": "High", "description": "Token exposure"},
            {"pattern": r"mysql://.*:.*@", "severity": "Critical", "description": "Database credentials in URI"},
        ],
        "malware_indicators": [
            {"pattern": r"\.exe|\.bat|\.cmd", "severity": "High", "description": "Windows executable"},
            {"pattern": r"/tmp/\S+\.(sh|py|pl)", "severity": "High", "description": "Suspicious script in /tmp"},
            {"pattern": r"chmod.*\+x", "severity": "Medium", "description": "Making script executable"},
            {"pattern": r"curl.*\|.*bash|wget.*\|.*python", "severity": "Critical", "description": "Piped execution (code injection)"},
        ],
        "exfiltration": [
            {"pattern": r"scp|rsync|sftp", "severity": "High", "description": "File transfer attempt"},
            {"pattern": r"tar.*gz|zip|rar", "severity": "Medium", "description": "Archive creation"},
            {"pattern": r"cat /etc/passwd|cat /etc/shadow|cat /etc/hosts", "severity": "High", "description": "System file access"},
            {"pattern": r"/dev/urandom|/dev/zero", "severity": "Medium", "description": "Data generation"},
        ],
        "persistence": [
            {"pattern": r"crontab|@reboot|\.bashrc|\.bash_profile", "severity": "High", "description": "Persistence mechanism"},
            {"pattern": r"iptables|firewall|ufw", "severity": "Medium", "description": "Firewall rule modification"},
            {"pattern": r"systemctl.*service|update-rc\.d", "severity": "High", "description": "Service persistence"},
        ],
        "privilege_escalation": [
            {"pattern": r"sudo -u|sudo -l|sudo -s", "severity": "High", "description": "Sudo abuse"},
            {"pattern": r"SUID|setuid|4[0-7]{3}", "severity": "High", "description": "SUID binary exploitation"},
            {"pattern": r"dd if=", "severity": "Medium", "description": "Direct disk access"},
        ]
    }

    with open(input_file, 'r') as f:
        lines = f.readlines()
    
    results["total_lines"] = len(lines)

    # 1. Suspicious Patterns Analysis
    if args.suspicious or args.all:
        console.print("[*] Analyzing for attack patterns...")
        for category, patterns in suspicious_patterns.items():
            for i, line in enumerate(lines):
                for pattern_obj in patterns:
                    pattern = pattern_obj["pattern"]
                    if re.search(pattern, line, re.IGNORECASE):
                        match_info = {
                            "line_number": i + 1,
                            "content": line.strip()[:200],
                            "pattern": pattern,
                            "category": category,
                            "severity": pattern_obj["severity"],
                            "description": pattern_obj["description"]
                        }
                        results["attack_patterns"][category].append(match_info)
                        results["suspicious_matches"].append(match_info)
                        
                        # Update severity summary
                        severity = pattern_obj["severity"].lower()
                        if severity in results["severity_summary"]:
                            results["severity_summary"][severity] += 1
        
        console.print(f"  [!] Found {len(results['suspicious_matches'])} suspicious matches")
        for category, matches in results["attack_patterns"].items():
            if matches:
                console.print(f"      • {category}: {len(matches)} detections")

    # 2. IP Extraction & Risk Assessment
    if args.ips or args.all:
        console.print("[*] Analyzing IP addresses and network activity...")
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        
        suspicious_ips = set()
        for i, line in enumerate(lines):
            matches = re.findall(ip_regex, line)
            for ip in matches:
                results["ip_frequencies"][ip] = results["ip_frequencies"].get(ip, 0) + 1
                
                # Risk assessment based on patterns
                if re.search(r"failed|error|denied|unauthorized", line, re.IGNORECASE):
                    if ip not in suspicious_ips:
                        suspicious_ips.add(ip)
        
        # Sort by frequency
        sorted_ips = sorted(results["ip_frequencies"].items(), key=lambda x: x[1], reverse=True)
        console.print(f"  [+] Analyzed {len(results['ip_frequencies'])} unique IPs")
        
        # Assess risk for suspicious IPs
        for ip in suspicious_ips:
            count = results["ip_frequencies"][ip]
            if count > 100:
                severity = "Critical"
            elif count > 50:
                severity = "High"
            elif count > 10:
                severity = "Medium"
            else:
                severity = "Low"
            
            results["ip_risk_assessment"][ip] = {
                "occurrence_count": count,
                "risk_level": severity,
                "suspicious_activity": True
            }
        
        if sorted_ips:
            console.print(f"  [+] Top IP: [bold cyan]{sorted_ips[0][0]}[/bold cyan] ({sorted_ips[0][1]} occurrences)")

    # 3. User Activity Analysis
    if args.all:
        console.print("[*] Analyzing user activity...")
        user_pattern = r"(?:user|username|login|uid=)\s*(\w+)"
        for line in lines:
            matches = re.findall(user_pattern, line, re.IGNORECASE)
            for user in matches:
                if user not in results["user_activity"]:
                    results["user_activity"][user] = {"count": 0, "activities": []}
                results["user_activity"][user]["count"] += 1
                if len(results["user_activity"][user]["activities"]) < 5:
                    results["user_activity"][user]["activities"].append(line.strip()[:100])

    # 4. Hunting Statistics
    results["hunting_statistics"] = {
        "patterns_analyzed": sum(len(p) for p in suspicious_patterns.values()),
        "total_detections": len(results["suspicious_matches"]),
        "categories_triggered": len([c for c in results["attack_patterns"] if results["attack_patterns"][c]]),
        "unique_ips": len(results["ip_frequencies"]),
        "suspicious_ips": len(results["ip_risk_assessment"]),
        "users_identified": len(results["user_activity"])
    }

    # Use getpass.getuser() which works reliably in schedulers/containers where os.getlogin() may fail
    audit_log(logger, getpass.getuser(), input_file, "forge/hunt", str(args), "SUCCESS")
    
    # Export
    formatted = format_output(results, args.output)
    console.print("\n[bold cyan]Threat Hunt Report:[/bold cyan]")
    console.print(f"[*] Critical: {results['severity_summary']['critical']}, High: {results['severity_summary']['high']}, Medium: {results['severity_summary']['medium']}")
    
    report_file = f"./logs/forge_hunt_{os.path.basename(input_file)}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.output}"
    with open(report_file, 'w') as f:
        f.write(formatted)
    console.print(f"[*] Hunting results saved to [bold cyan]{report_file}[/bold cyan]")

if __name__ == "__main__":
    main()
