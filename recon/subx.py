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
    import socket
    import dns.resolver
    
    console.print(f"[*] Starting subdomain enumeration for: [bold white]{args.domain}[/bold white]")
    logger.info(f"Subdomain enum started: domain={args.domain}")
    
    results = {
        "domain": args.domain,
        "subdomains": [],
        "ips": {},
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Common subdomains to check
    common_subs = [
        "www", "mail", "ftp", "admin", "api", "staging", "dev", "test",
        "blog", "shop", "store", "app", "mobile", "m", "webmail", "smtp",
        "imap", "pop", "ns1", "ns2", "vpn", "server", "database"
    ]
    
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist, 'r') as f:
            common_subs = [line.strip() for line in f.readlines()]
        console.print(f"[*] Loaded {len(common_subs)} subdomains from wordlist")
    
    console.print("[*] Performing DNS lookups...")
    found_count = 0
    
    for sub in common_subs:
        try:
            full_domain = f"{sub}.{args.domain}"
            # Try to resolve the subdomain
            answers = dns.resolver.resolve(full_domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                results["subdomains"].append(full_domain)
                results["ips"][full_domain] = ip
                console.print(f"  [+] {full_domain:30} → {ip}")
                found_count += 1
        except Exception:
            pass  # Subdomain not found
    
    if args.all or args.passive:
        console.print("[*] Checking DNS records (MX, TXT, NS)...")
        try:
            mx = dns.resolver.resolve(args.domain, 'MX')
            console.print(f"  [+] MX Records: {[str(r.exchange) for r in mx]}")
        except:
            pass
    
    console.print(f"\n[bold green][+] Enumeration complete: {found_count} subdomains found[/bold green]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Results:")
        import json
        console.print(json.dumps(results, indent=2))
    
    audit_log(logger, getpass.getuser(), args.domain, "recon/subx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
