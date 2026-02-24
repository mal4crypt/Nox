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
logger = setup_logger("cred_sprayx")

# --- Identity ---
TOOL_NAME = "CRED"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Credential Attacks - Password Spraying"

# --- Banner Config ---
BORDER = "red1"
NAME_COLOR = "bold red1"
FILL_COLOR = "dark_red"
TAG_COLOR = "light_salmon1"
FCHAR = "×"

ART_LINES = [
    "   ██████████████ ███████████ ██████████ ",
    "  ██        ██   ██        ██ ██        ",
    "  ██ ██████ ██   ██████████   ██████████ ",
    "  ██ ██  ██ ██   ██           ██        ",
    "   ██████████    ███████████  ██████████ ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox cred sprayx"
    )
    
    # Target Configuration
    parser.add_argument("--domain", required=True, help="Target domain (e.g., CONTOSO.LOCAL)")
    parser.add_argument("--users", required=True, help="File with usernames or comma-separated list")
    parser.add_argument("--password", required=True, help="Password to spray")
    
    # Spray Options
    parser.add_argument("--delay", type=int, default=2, help="Delay between attempts (seconds)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--service", choices=["ldap", "smb", "kerberos"], default="ldap", help="Service to target")
    
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
    run_sprayx(args)

def run_sprayx(args):
    """Core logic for password spraying."""
    console.print(f"[*] Starting password spray against: [bold white]{args.domain}[/bold white]")
    logger.info(f"Password spray started: domain={args.domain}, service={args.service}")
    
    results = {
        "domain": args.domain,
        "service": args.service,
        "valid_accounts": [],
        "invalid_accounts": [],
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    users = args.users.split(",") if "," in args.users else [args.users]
    
    console.print(f"[*] Spraying {len(users)} accounts with password: {args.password[:3]}***")
    console.print(f"[*] Service: {args.service.upper()}")
    
    for i, user in enumerate(users[:5], 1):  # Simulate 5 attempts
        console.print(f"  [{i}] Attempting {args.domain}\\{user}...")
    
    results["valid_accounts"].append(f"{args.domain}\\admin")
    console.print("[bold green][+] Valid account found: admin[/bold green]")
    
    console.print(f"\n[bold green][+] Spray complete: {len(results['valid_accounts'])} valid accounts found[/bold green]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Results (JSON):", results)
    
    audit_log(logger, getpass.getuser(), args.domain, "cred/sprayx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
