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
    Core logic for threat hunting in logs.
    """
    input_file = args.file
    if not os.path.exists(input_file):
        console.print(f"[bold red]Error:[/bold red] Log file {input_file} not found.")
        return

    console.print(f"[*] Hunting in: [bold white]{input_file}[/bold white]...")
    logger.info(f"Forge Hunt started: file={input_file}")
    
    results = {
        "file": input_file,
        "suspicious_matches": [],
        "ip_frequencies": {},
        "custom_matches": [],
        "timestamp": datetime.datetime.now().isoformat()
    }

    suspicious_patterns = [
        r"base64", r"nc -e", r"bash -i", r"python -c", r"wget ", r"curl ",
        r"/tmp/", r"/dev/tcp", r"whoami", r"cat /etc/passwd"
    ]

    with open(input_file, 'r') as f:
        lines = f.readlines()

    # 1. Suspicious Patterns
    if args.suspicious or args.all:
        console.print("[*] Searching for suspicious shell commands...")
        for i, line in enumerate(lines):
            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    results["suspicious_matches"].append({"line": i+1, "content": line.strip(), "pattern": pattern})
        console.print(f"  [+] Found {len(results['suspicious_matches'])} suspicious occurrences.")

    # 2. IP Extraction & Frequency
    if args.ips or args.all:
        console.print("[*] Analyzing IP address frequencies...")
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        for line in lines:
            matches = re.findall(ip_regex, line)
            for ip in matches:
                results["ip_frequencies"][ip] = results["ip_frequencies"].get(ip, 0) + 1
        
        # Sort by frequency
        sorted_ips = sorted(results["ip_frequencies"].items(), key=lambda x: x[1], reverse=True)
        console.print(f"  [+] Analyzed {len(results['ip_frequencies'])} unique IPs.")
        if sorted_ips:
            console.print(f"  [+] Top IP: [bold cyan]{sorted_ips[0][0]}[/bold cyan] ({sorted_ips[0][1]} hits)")

    # Use getpass.getuser() which works reliably in schedulers/containers where os.getlogin() may fail
    audit_log(logger, getpass.getuser(), input_file, "forge/hunt", str(args), "SUCCESS")
    
    # Export
    formatted = format_output(results, args.output)
    console.print("\n[bold cyan]Threat Hunt Report:[/bold cyan]")
    
    report_file = f"./logs/forge_hunt_{os.path.basename(input_file)}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.output}"
    with open(report_file, 'w') as f:
        f.write(formatted)
    console.print(f"[*] Hunting results saved to [bold cyan]{report_file}[/bold cyan]")

if __name__ == "__main__":
    main()
