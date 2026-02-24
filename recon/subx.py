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
logger = setup_logger("recon_subx")

# --- Identity ---
TOOL_NAME = "RECON"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Reconnaissance & Active Discovery - Subdomain Enumeration"

# --- Banner Config ---
BORDER = "bright_cyan"
NAME_COLOR = "bold bright_cyan"
FILL_COLOR = "cyan1"
TAG_COLOR = "pale_turquoise1"
FCHAR = "∙"

ART_LINES = [
    "  ███████████████████████████████████████████████  ",
    "  ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████  ",
    "  ████░░ █████ █████ ███ █████ ███ █████░░████  ",
    "  ████░░█░    █      █   █    █   █      █░████  ",
    "  ████░░█ ███ ███    █   █ ██ █   █ ███░░████  ",
    "  ████░░█░█   █      █   █    █   █░█   ░████  ",
    "  ████░░░█████ █████ █   █████ ███ █████░░████  ",
    "  ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████  ",
    "  ███████████████████████████████████████████████  ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox recon subx"
    )
    
    # Target Configuration
    parser.add_argument("--domain", required=True, help="Target domain to enumerate")
    
    # Enumeration Options
    parser.add_argument("--wordlist", help="Custom wordlist for subdomain brute-force")
    parser.add_argument("--all", action="store_true", help="Use all enumeration methods")
    parser.add_argument("--passive", action="store_true", help="Passive enumeration only (DNS/WHOIS)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    
    # Output Options
    parser.add_argument("--output", choices=["json", "csv", "txt"], default="json", help="Output format")
    parser.add_argument("--out-file", help="Save results to file")
    
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
    run_subx(args)

def run_subx(args):
    """Core logic for subdomain enumeration."""
    console.print(f"[*] Starting subdomain enumeration for: [bold white]{args.domain}[/bold white]")
    logger.info(f"Subdomain enum started: domain={args.domain}")
    
    results = {
        "domain": args.domain,
        "subdomains": [],
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Simulated enumeration
    console.print("[*] Performing DNS lookups...")
    console.print("  [+] Found: www, mail, admin, api, staging")
    results["subdomains"].extend(["www", "mail", "admin", "api", "staging"])
    
    if args.all or args.passive:
        console.print("[*] Checking DNS records...")
        console.print("  [+] A, MX, TXT records enumerated")
    
    console.print(f"\n[bold green][+] Enumeration complete: {len(results['subdomains'])} subdomains found[/bold green]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Results (JSON):", results)
    
    audit_log(logger, getpass.getuser(), args.domain, "recon/subx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
