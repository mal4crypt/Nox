import sys
import argparse
import os
import requests
import whois
import dns.resolver
from rich.console import Console
from utils.banner import print_nox_banner
from utils.logger import setup_logger, audit_log
from utils.formatter import format_output
import datetime

console = Console()
logger = setup_logger("spekt_intel")

# --- Identity ---
TOOL_NAME = "SPEKT"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "OSINT Automation & Intelligence Gathering"

# --- Banner Config ---
BORDER = "spring_green3"
NAME_COLOR = "bold spring_green3"
FILL_COLOR = "medium_spring_green"
TAG_COLOR = "aquamarine1"
FCHAR = "─"

ART_LINES = [
    " ░▒▓███████▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░ ",
    "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
    "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
    " ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░   ░▒▓█▓▒░     ",
    "       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
    "       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
    "░▒▓███████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox.py spekt intel"
    )
    
    # Target Configuration
    parser.add_argument("--target", required=True, help="Target domain or IP address")
    
    # OSINT Options
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--geo", action="store_true", help="Perform GeoIP lookup (for IPs)")
    parser.add_argument("--all", action="store_true", help="Perform all basic intelligence tasks")
    
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
    run_osint(args)

def run_osint(args):
    """
    Core logic for OSINT gathering.
    """
    target = args.target
    console.print(f"[*] Gathering intelligence on: [bold white]{target}[/bold white]...")
    logger.info(f"OSINT Scan started: target={target}")
    
    results = {
        "target": target,
        "dns": {},
        "whois": {},
        "geo": {},
        "timestamp": datetime.datetime.now().isoformat()
    }

    # 1. DNS Recon
    if args.dns or args.all:
        console.print("[*] Performing DNS reconnaissance...")
        try:
            records = ['A', 'MX', 'TXT']
            for record in records:
                try:
                    answers = dns.resolver.resolve(target, record)
                    results["dns"][record] = [str(rdata) for rdata in answers]
                    console.print(f"  [+] {record} records found.")
                except Exception:
                    pass
        except Exception as e:
            console.print(f"[bold red][!][/bold red] DNS Recon failed: {e}")

    # 2. WHOIS
    if args.whois or args.all:
        console.print("[*] Retrieving WHOIS information...")
        try:
            w = whois.whois(target)
            results["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
            console.print("  [+] WHOIS records retrieved.")
        except Exception as e:
            console.print(f"[bold red][!][/bold red] WHOIS Lookup failed: {e}")

    # 3. GeoIP
    if args.geo or args.all:
        console.print("[*] Performing GeoIP lookup...")
        try:
            # Simple API call for geoip
            response = requests.get(f"http://ip-api.com/json/{target}", timeout=5)
            if response.status_code == 200:
                results["geo"] = response.json()
                console.print(f"  [+] Location: {results['geo'].get('city')}, {results['geo'].get('country')}")
        except Exception as e:
            console.print(f"[bold red][!][/bold red] GeoIP Lookup failed: {e}")

    audit_log(logger, os.getlogin(), target, "spekt/intel", str(args), "SUCCESS")
    
    # Export
    formatted = format_output(results, args.output)
    console.print("\n[bold cyan]Intelligence Report:[/bold cyan]")
    console.print(formatted)
    
    report_file = f"./logs/spekt_intel_{target.replace('.','_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.output}"
    with open(report_file, 'w') as f:
        f.write(formatted)
    console.print(f"[*] Intelligence results saved to [bold cyan]{report_file}[/bold cyan]")

if __name__ == "__main__":
    main()
