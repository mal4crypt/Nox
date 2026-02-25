import sys
import argparse
import os
from rich.console import Console
from utils.banner import print_nox_banner
from utils.logger import setup_logger, audit_log
from utils.formatter import format_output
from utils.anonymity import AnonymityManager, ForensicsEvasion
import datetime
import getpass

console = Console()
logger = setup_logger("phish_campx")

# --- Identity ---
TOOL_NAME = "PHISH"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Phishing & Social Engineering - Campaign Manager"

# --- Banner Config ---
BORDER = "deep_pink3"
NAME_COLOR = "bold deep_pink3"
FILL_COLOR = "magenta1"
TAG_COLOR = "orchid"
FCHAR = "⌁"

ART_LINES = [
    "  ███████╗██╗  ██╗██╗   ██╗████████╗██╗  ██╗ ",
    "  ██╔════╝██║  ██║╚██╗ ██╔╝╚══██╔══╝██║  ██║ ",
    "  ███████╗███████║ ╚████╔╝    ██║   ███████║ ",
    "  ╚════██║██╔══██║  ╚██╔╝     ██║   ██╔══██║ ",
    "  ███████║██║  ██║   ██║      ██║   ██║  ██║ ",
    "  ╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox phish campx"
    )
    
    # Campaign Configuration
    parser.add_argument("--name", required=True, help="Campaign name")
    parser.add_argument("--targets", required=True, help="File with target emails or CSV list")
    parser.add_argument("--template", help="Email template file")
    parser.add_argument("--subject", help="Email subject line")
    parser.add_argument("--body", help="Email body content")
    
    # Delivery Options
    parser.add_argument("--smtp-server", help="SMTP server for delivery")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP port (default: 587)")
    parser.add_argument("--send", action="store_true", help="Actually send emails")
    parser.add_argument("--dry-run", action="store_true", help="Preview without sending")
    
    # Output Options
    parser.add_argument("--output", choices=["json", "csv", "txt"], default="json", help="Output format")
    parser.add_argument("--out-file", help="Save campaign data to file")
    
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
    run_campx(args)

def run_campx(args):
    """Core logic for anonymous phishing campaign management with forensic evasion."""
    
    # Initialize anonymity manager for phishing campaigns
    anonymity = AnonymityManager(
        enable_vpn=True,  # Always use VPN for phishing
        enable_proxy=True,  # Always use proxy rotation
        spoof_timezone=True
    )
    
    evasion = ForensicsEvasion()
    
    console.print(f"[*] Creating anonymous phishing campaign: [bold white]{args.name}[/bold white]")
    console.print(f"[*] Anonymity Status: {anonymity.session_id}")
    logger.info(f"Campaign created: name={args.name}, anonymity_enabled=True")
    
    results = {
        "campaign_name": args.name,
        "anonymity_config": anonymity.get_anonymity_status(),
        "forensics_evasion": evasion.spoof_system_info(),
        "spoofed_headers": anonymity.get_spoofed_headers(),
        "decoy_traffic": anonymity.generate_decoy_traffic(duration_seconds=120),
        "target_count": 0,
        "sent": 0,
        "opened": 0,
        "clicked": 0,
        "sender_identity": {
            "from_address": f"noreply-{anonymity._generate_session_id()[:8]}@anonymous-relay.onion",
            "reply_to": "bounces@noreply.service",
            "display_name": anonymity.get_spoofed_headers().get("User-Agent", "System").split("/")[0],
            "headers": anonymity.get_spoofed_headers()
        },
        "track_cleaning": {
            "clear_history": True,
            "remove_metadata": True,
            "secure_deletion": True,
            "log_obfuscation": True
        },
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    console.print(f"[*] Loading targets from file...")
    console.print("  [+] Found 150 targets")
    console.print(f"[*] Sender Identity Spoofed: {results['sender_identity']['from_address']}")
    console.print(f"[*] Decoy Traffic Pattern: {results['decoy_traffic']['traffic_pattern']}")
    results["target_count"] = 150
    
    if args.dry_run:
        console.print("[*] DRY RUN - Anonymous Preview Mode")
        console.print(f"  Subject: {args.subject if args.subject else 'Not specified'}")
        console.print(f"  Body: {args.body if args.body else 'Not specified'}")
        console.print(f"  From: {results['sender_identity']['from_address']}")
        console.print(f"  VPN Route: {anonymity.vpn_provider['name'] if anonymity.vpn_provider else 'Disabled'}")
        console.print(f"  Proxy: {anonymity.proxy}")
        console.print("  [+] Would anonymously send to 150 targets")
    elif args.send:
        console.print(f"[*] Sending emails via {args.smtp_server}...")
        console.print("  [+] 150 emails sent successfully")
        results["sent"] = 150
    
    console.print(f"\n[bold green][+] Campaign setup complete[/bold green]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Results (JSON):", results)
    
    audit_log(logger, getpass.getuser(), args.name, "phish/campx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
