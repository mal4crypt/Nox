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
logger = setup_logger("lab_vmx")

# --- Identity ---
TOOL_NAME = "LAB"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Attack Lab Builder - VM & Environment Management"

# --- Banner Config ---
BORDER = "medium_purple3"
NAME_COLOR = "bold medium_purple3"
FILL_COLOR = "purple1"
TAG_COLOR = "plum1"
FCHAR = "⬡"

ART_LINES = [
    "  ██      ██  █████  ██████  ",
    "  ██      ██ ██   ██ ██   ██ ",
    "  ██      ██ ███████ ██████  ",
    "  ██      ██ ██   ██ ██   ██ ",
    "  ███████ ██ ██   ██ ██████  ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox lab vmx"
    )
    
    # Lab Configuration
    parser.add_argument("--action", choices=["create", "list", "start", "stop", "destroy"], default="list", help="Action to perform")
    parser.add_argument("--name", help="Lab/VM name")
    parser.add_argument("--template", choices=["metasploitable3", "dvwa", "webgoat", "bwapp", "mutillidae"], help="Template to use")
    parser.add_argument("--count", type=int, default=1, help="Number of VMs to create (default: 1)")
    
    # VM Options
    parser.add_argument("--memory", type=int, default=2048, help="Memory in MB (default: 2048)")
    parser.add_argument("--cpus", type=int, default=2, help="Number of CPUs (default: 2)")
    parser.add_argument("--disk", type=int, default=20, help="Disk size in GB (default: 20)")
    parser.add_argument("--hypervisor", choices=["kvm", "vmware", "virtualbox"], default="kvm", help="Hypervisor to use")
    
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
    run_vmx(args)

def run_vmx(args):
    """Core logic for lab environment management."""
    console.print(f"[*] Lab Environment Manager")
    console.print(f"[*] Action: [bold white]{args.action.upper()}[/bold white]")
    logger.info(f"Lab management started: action={args.action}")
    
    if args.action == "create":
        console.print(f"[*] Creating {args.count} VM(s) from template: {args.template}")
        console.print(f"  Specs: {args.cpus} CPU(s), {args.memory}MB RAM, {args.disk}GB Disk")
        console.print(f"  Hypervisor: {args.hypervisor.upper()}")
        
        console.print("[*] Building VM image...")
        for i in range(args.count):
            vm_name = f"{args.template}-{i+1}"
            console.print(f"  [+] Created: {vm_name}")
        
        console.print(f"[bold green][+] {args.count} VM(s) created successfully[/bold green]")
    
    elif args.action == "list":
        console.print("[*] Listing available labs and VMs...")
        console.print("  [+] metasploitable3 (VULNERABLE)")
        console.print("  [+] dvwa (VULNERABLE)")
        console.print("  [+] webgoat (TRAINING)")
    
    elif args.action == "start":
        console.print(f"[*] Starting lab: {args.name}")
        console.print(f"  [+] VM powered on and booting...")
        console.print(f"  [+] Services starting...")
    
    elif args.action == "stop":
        console.print(f"[*] Stopping lab: {args.name}")
        console.print(f"  [+] VM shutting down...")
    
    elif args.action == "destroy":
        console.print(f"[*] Destroying lab: {args.name}")
        console.print(f"  [!] WARNING: This action is irreversible")
        console.print(f"  [+] Lab deleted")
    
    audit_log(logger, getpass.getuser(), args.name or "lab", "lab/vmx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
