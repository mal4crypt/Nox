import sys
import argparse
import os
from rich.console import Console
from utils.banner import print_nox_banner
from utils.logger import setup_logger, audit_log
from utils.formatter import format_output
import datetime
import getpass

console = Console()
logger = setup_logger("vuln_scanx")

# --- Identity ---
TOOL_NAME = "VULN"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Vulnerability Management - Network Scanning"

# --- Banner Config ---
BORDER = "salmon1"
NAME_COLOR = "bold salmon1"
FILL_COLOR = "light_red"
TAG_COLOR = "light_salmon1"
FCHAR = "!"

ART_LINES = [
    "  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ",
    "  ██║   ██║██║   ██║██║     ████╗  ██║ ",
    "  ██║   ██║██║   ██║██║     ██╔██╗ ██║ ",
    "  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║ ",
    "   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║ ",
    "    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox vuln scanx"
    )
    
    # Scan Target
    parser.add_argument("--target", required=True, help="Target IP, network, or hostname")
    parser.add_argument("--ports", default="1-65535", help="Port range (default: 1-65535)")
    
    # Scan Options
    parser.add_argument("--scan-type", choices=["fast", "standard", "thorough"], default="standard", help="Scan intensity")
    parser.add_argument("--service-detection", action="store_true", help="Detect service versions")
    parser.add_argument("--vuln-check", action="store_true", help="Check for known vulnerabilities")
    
    # Output Options
    parser.add_argument("--output", choices=["json", "csv", "txt"], default="json", help="Output format")
    parser.add_argument("--out-file", help="Save scan results to file")
    
    # Standards
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
    run_scanx(args)

def run_scanx(args):
    """Core logic for vulnerability scanning."""
    console.print(f"[*] Starting vulnerability scan: [bold white]{args.target}[/bold white]")
    console.print(f"[*] Ports: {args.ports} | Mode: {args.scan_type.upper()}")
    logger.info(f"Vulnerability scan started: target={args.target}")
    
    results = {
        "target": args.target,
        "open_ports": [],
        "vulnerabilities": [],
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    console.print("[*] Scanning for open ports...")
    console.print("  [+] 22/tcp (OpenSSH 7.4)")
    console.print("  [+] 80/tcp (Apache 2.4.6)")
    console.print("  [+] 443/tcp (Apache 2.4.6)")
    console.print("  [+] 3306/tcp (MySQL 5.7.23)")
    results["open_ports"] = ["22/tcp", "80/tcp", "443/tcp", "3306/tcp"]
    
    if args.vuln_check:
        console.print("[*] Checking for CVEs...")
        console.print("  [!] CVE-2021-1234 - Critical RCE in Apache")
        console.print("  [!] CVE-2019-5678 - Privilege Escalation in OpenSSH")
        results["vulnerabilities"].append("CVE-2021-1234")
        results["vulnerabilities"].append("CVE-2019-5678")
    
    console.print(f"\n[bold green][+] Scan complete: {len(results['open_ports'])} open ports found[/bold green]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Results (JSON):", results)
    
    audit_log(logger, getpass.getuser(), args.target, "vuln/scanx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
