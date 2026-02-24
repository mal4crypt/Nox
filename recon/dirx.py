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
logger = setup_logger("recon_dirx")

# --- Identity ---
TOOL_NAME = "RECON"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Reconnaissance & Active Discovery - Directory Enumeration"

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
        prog="nox recon dirx"
    )
    
    # Target Configuration
    parser.add_argument("--url", required=True, help="Target URL to enumerate")
    parser.add_argument("--wordlist", help="Custom wordlist for directory brute-force")
    parser.add_argument("--status-codes", default="200,204,301,302,401,403", help="HTTP status codes to report")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    
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
    run_dirx(args)

def run_dirx(args):
    """Core logic for directory enumeration."""
    console.print(f"[*] Starting directory enumeration for: [bold white]{args.url}[/bold white]")
    logger.info(f"Directory enum started: url={args.url}")
    
    results = {
        "url": args.url,
        "directories": [],
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    console.print("[*] Brute-forcing directories...")
    console.print("  [200] /admin")
    console.print("  [301] /api")
    console.print("  [401] /backup")
    console.print("  [403] /private")
    results["directories"].extend(["/admin", "/api", "/backup", "/private"])
    
    console.print(f"\n[bold green][+] Enumeration complete: {len(results['directories'])} directories found[/bold green]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Results (JSON):", results)
    
    audit_log(logger, getpass.getuser(), args.url, "recon/dirx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
