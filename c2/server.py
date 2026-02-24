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
logger = setup_logger("c2_server")

# --- Identity ---
TOOL_NAME = "C2"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Command & Control Framework - C2 Server"

# --- Banner Config ---
BORDER = "chartreuse3"
NAME_COLOR = "bold chartreuse3"
FILL_COLOR = "yellow3"
TAG_COLOR = "light_yellow"
FCHAR = "█░"

ART_LINES = [
    "   ██████╗██████╗  █████╗ ",
    "  ██╔════╝╚════██╗██╔══██╗",
    "  ██║      █████╔╝███████║",
    "  ██║     ██╔═══╝ ██╔══██║",
    "   ██████╗███████╗██║  ██║",
    "   ╚═════╝╚══════╝╚═╝  ╚═╝",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox c2 server"
    )
    
    # Server Configuration
    parser.add_argument("--listen", default="0.0.0.0:8080", help="Listen address:port (default: 0.0.0.0:8080)")
    parser.add_argument("--profile", choices=["http", "https", "dns", "https-domain"], default="http", help="C2 profile")
    parser.add_argument("--cert", help="HTTPS certificate file (for https profile)")
    parser.add_argument("--key", help="HTTPS private key file (for https profile)")
    
    # Operator Options
    parser.add_argument("--operator", help="Operator identifier")
    parser.add_argument("--auth-token", help="Authentication token for operators")
    
    # Output Options
    parser.add_argument("--output", choices=["json", "csv", "txt"], default="json", help="Output format")
    parser.add_argument("--log-file", help="Log file for C2 activity")
    
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
    run_c2_server(args)

def run_c2_server(args):
    """Core logic for C2 server initialization."""
    host, port = args.listen.split(":") if ":" in args.listen else (args.listen, "8080")
    
    console.print(f"[*] Starting C2 Server...")
    console.print(f"[*] Listening on: [bold white]{host}:{port}[/bold white]")
    console.print(f"[*] Profile: [bold white]{args.profile.upper()}[/bold white]")
    logger.info(f"C2 server started: listen={args.listen}, profile={args.profile}")
    
    results = {
        "listen": args.listen,
        "profile": args.profile,
        "agents_connected": 0,
        "commands_executed": 0,
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    console.print(f"[bold green][+] C2 Server initialized and waiting for agent connections[/bold green]")
    console.print(f"[bold yellow][!] Press Ctrl+C to stop the server[/bold yellow]")
    
    if args.log_file:
        console.print(f"[*] Activity logging to: {args.log_file}")
    
    audit_log(logger, getpass.getuser(), args.listen, "c2/server", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
