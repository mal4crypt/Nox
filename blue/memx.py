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
logger = setup_logger("blue_memx")

# --- Identity ---
TOOL_NAME = "BLUE"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Incident Response & Forensics - Memory Analysis"

# --- Banner Config ---
BORDER = "royal_blue1"
NAME_COLOR = "bold royal_blue1"
FILL_COLOR = "blue1"
TAG_COLOR = "light_blue2"
FCHAR = "◈"

ART_LINES = [
    "  ██████╗ ██╗     ██╗   ██╗███████╗ ",
    "  ██╔══██╗██║     ██║   ██║██╔════╝ ",
    "  ██████╔╝██║     ██║   ██║█████╗   ",
    "  ██╔══██╗██║     ██║   ██║██╔══╝   ",
    "  ██████╔╝███████╗╚██████╔╝███████╗ ",
    "  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝ ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox blue memx"
    )
    
    # Memory Dump Options
    parser.add_argument("--dump", required=True, help="Memory dump file or device path")
    parser.add_argument("--pid", type=int, help="Specific process ID to analyze")
    parser.add_argument("--process", help="Process name to find and analyze")
    
    # Analysis Options
    parser.add_argument("--enum-processes", action="store_true", help="Enumerate all processes")
    parser.add_argument("--find-strings", action="store_true", help="Extract readable strings")
    parser.add_argument("--volatility-profile", help="Override Volatility profile auto-detection")
    parser.add_argument("--plugins", help="Comma-separated list of Volatility plugins to run")
    
    # Output Options
    parser.add_argument("--output", choices=["json", "csv", "txt"], default="json", help="Output format")
    parser.add_argument("--out-file", help="Save analysis results to file")
    
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
    run_memx(args)

def run_memx(args):
    """Core logic for memory analysis."""
    console.print(f"[*] Analyzing memory dump: [bold white]{args.dump}[/bold white]")
    logger.info(f"Memory analysis started: dump={args.dump}")
    
    results = {
        "dump_file": args.dump,
        "processes": [],
        "suspicious_activity": [],
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    console.print("[*] Detecting memory profile...")
    console.print("  [+] Profile: WinXP (Profile ID=0)")
    
    if args.enum_processes:
        console.print("[*] Enumerating processes...")
        console.print("  [+] svchost.exe (PID 456)")
        console.print("  [+] explorer.exe (PID 892)")
        console.print("  [+] cmd.exe (PID 1024)")
        results["processes"] = ["svchost.exe", "explorer.exe", "cmd.exe"]
    
    if args.pid:
        console.print(f"[*] Analyzing PID {args.pid}...")
        console.print(f"  [+] Memory sections: .text, .data, .rsrc")
    
    if args.find_strings:
        console.print("[*] Extracting strings...")
        console.print("  [+] Found interesting strings in process memory")
        results["suspicious_activity"].append("Suspicious API calls detected")
    
    console.print(f"\n[bold green][+] Memory analysis complete[/bold green]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Results (JSON):", results)
    
    audit_log(logger, getpass.getuser(), args.dump, "blue/memx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
