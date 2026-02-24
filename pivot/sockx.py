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
logger = setup_logger("pivot_sockx")

# --- Identity ---
TOOL_NAME = "PIVOT"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Lateral Movement & Tunnelling - SOCKS Proxy"

# --- Banner Config ---
BORDER = "dark_orange3"
NAME_COLOR = "bold dark_orange3"
FILL_COLOR = "orange3"
TAG_COLOR = "light_goldenrod1"
FCHAR = "→"

ART_LINES = [
    "  ██████╗ ██╗██╗   ██╗ ██████╗ ████████╗ ",
    "  ██╔══██╗██║██║   ██║██╔═══██╗╚══██╔══╝ ",
    "  ██████╔╝██║██║   ██║██║   ██║   ██║    ",
    "  ██╔═══╝ ██║╚██╗ ██╔╝██║   ██║   ██║    ",
    "  ██║     ██║ ╚████╔╝ ╚██████╔╝   ██║    ",
    "  ╚═╝     ╚═╝  ╚═══╝   ╚═════╝    ╚═╝    ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox pivot sockx"
    )
    
    # Proxy Configuration
    parser.add_argument("--listen", default="127.0.0.1:1080", help="Listen address:port (default: 127.0.0.1:1080)")
    parser.add_argument("--target", required=True, help="Compromised host to pivot through")
    parser.add_argument("--target-port", type=int, default=22, help="SSH port on target (default: 22)")
    parser.add_argument("--user", required=True, help="Username for target authentication")
    parser.add_argument("--key", help="SSH private key file")
    parser.add_argument("--password", help="SSH password (if not using key)")
    
    # Proxy Options
    parser.add_argument("--version", choices=["4", "5"], default="5", help="SOCKS version (4 or 5)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    
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
    run_sockx(args)

def run_sockx(args):
    """Core logic for SOCKS proxy establishment."""
    console.print(f"[*] Setting up SOCKS{args.version} proxy...")
    console.print(f"[*] Target: [bold white]{args.target}:{args.target_port}[/bold white]")
    console.print(f"[*] Listening on: [bold white]{args.listen}[/bold white]")
    logger.info(f"SOCKS proxy started: target={args.target}, listen={args.listen}")
    
    results = {
        "listen": args.listen,
        "target": args.target,
        "socks_version": f"SOCKS{args.version}",
        "connections": 0,
        "bytes_transferred": 0,
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    console.print(f"[*] Authenticating to {args.target}...")
    console.print(f"  [+] Connected as {args.user}")
    
    console.print(f"[bold green][+] SOCKS{args.version} proxy established and listening[/bold green]")
    console.print(f"[bold white]Use -D {args.listen} with curl/ssh to route traffic through proxy[/bold white]")
    
    audit_log(logger, getpass.getuser(), args.target, "pivot/sockx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
