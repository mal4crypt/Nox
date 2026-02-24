import sys
import argparse
import subprocess
import os
from rich.console import Console
from utils.banner import print_nox_banner
from utils.logger import setup_logger, audit_log
from utils.formatter import format_output
import datetime

console = Console()
logger = setup_logger("mobi_droid")

# --- Identity ---
TOOL_NAME = "MOBI"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Mobile Application Pentesting Suite - Android Enumeration"

# --- Banner Config ---
BORDER = "purple"
NAME_COLOR = "bold purple"
FILL_COLOR = "medium_purple1"
TAG_COLOR = "orchid1"
FCHAR = "Ⓜ"

ART_LINES = [
    "                         ___            ",
    "                        (   )      .-.  ",
    " ___ .-. .-.     .--.    | |.-.   ( __) ",
    "(   )   \'   \\   /    \\   | /   \\  (\'\'\") ",
    " |  .-.  .-. ; |  .-. ;  |  .-. |  | |  ",
    " | |  | |  | | | |  | |  | |  | |  | |  ",
    " | |  | |  | | | |  | |  | |  | |  | |  ",
    " | |  | |  | | | |  | |  | |  | |  | |  ",
    " | |  | |  | | | \'  | |  | \'  | |  | |  ",
    " | |  | |  | | \'  `-\' /  \' `-\' ;   | |  ",
    "(___)(___)(___) `.__.\'    `.__.   (___) "
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox.py mobi droid"
    )
    
    # ADB Configuration
    parser.add_argument("--serial", help="Target device serial number (optional)")
    
    # Actions
    parser.add_argument("--list-packages", action="store_true", help="List all installed packages")
    parser.add_argument("--check-debug", action="store_true", help="Check if device is debuggable")
    parser.add_argument("--pull", help="Package name to pull APK from")
    
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
    run_droid(args)

def run_droid(args):
    """
    Core logic for Android enumeration.
    """
    adb_cmd = ["adb"]
    if args.serial:
        adb_cmd.extend(["-s", args.serial])
    
    console.print(f"[*] Target Device: [bold white]{args.serial if args.serial else 'Default'}[/bold white]")
    logger.info(f"Droid Scan started: device={args.serial}")
    
    # 1. Check Connection
    try:
        subprocess.check_output(adb_cmd + ["get-state"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        console.print("[bold red]Error:[/bold red] ADB device not found or offline.")
        return
    except FileNotFoundError:
        console.print("[bold red]Error:[/bold red] ADB command not found. Please install adb.")
        return

    # 2. List Packages
    if args.list_packages:
        console.print("[*] Retrieving package list...")
        try:
            output = subprocess.check_output(adb_cmd + ["shell", "pm", "list", "packages"]).decode()
            packages = [line.split(":")[1].strip() for line in output.splitlines() if ":" in line]
            console.print(f"  [+] Found {len(packages)} packages.")
            # For brevity in console, we don't print all. In report we do.
        except Exception as e:
            console.print(f"[bold red][!][/bold red] Failed to list packages: {e}")

    # 3. Check Debug
    if args.check_debug:
        console.print("[*] Checking ro.debuggable property...")
        try:
            val = subprocess.check_output(adb_cmd + ["shell", "getprop", "ro.debuggable"]).decode().strip()
            if val == "1":
                console.print("[bold red][!] Device is DEBUGGABLE (ro.debuggable=1)[/bold red]")
            else:
                console.print("[green][+] Device is not debuggable.[/green]")
        except Exception as e:
            console.print(f"[bold red][!][/bold red] Failed to check debug status: {e}")

    # 4. Pull APK
    if args.pull:
        package = args.pull
        console.print(f"[*] Attemping to pull APK for: [bold cyan]{package}[/bold cyan]")
        try:
            path_output = subprocess.check_output(adb_cmd + ["shell", "pm", "path", package]).decode().strip()
            if "package:" in path_output:
                apk_path = path_output.split(":")[1]
                subprocess.check_call(adb_cmd + ["pull", apk_path, f"./logs/{package}.apk"])
                console.print(f"[bold green][+] APK pulled successfully to ./logs/{package}.apk[/bold green]")
            else:
                console.print(f"[bold red][!] Package {package} not found.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!][/bold red] Failed to pull APK: {e}")

    audit_log(logger, os.getlogin(), args.serial if args.serial else "ADB", "mobi/droid", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
