import sys
import argparse
import serial
import serial.tools.list_ports
import os
from rich.console import Console
from utils.banner import print_nox_banner
from utils.logger import setup_logger, audit_log
from utils.formatter import format_output
import datetime

console = Console()
logger = setup_logger("firm_flash")

# --- Identity ---
TOOL_NAME = "FIRM"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Hardware & Embedded Security Suite - Firmware Extraction"

# --- Banner Config ---
BORDER = "red"
NAME_COLOR = "bold red"
FILL_COLOR = "indian_red"
TAG_COLOR = "misty_rose1"
FCHAR = "█"

ART_LINES = [
    "    ███████╗██╗██████╗ ███╗   ███╗",
    "    ██╔════╝██║██╔══██╗████╗ ████║",
    "    █████╗  ██║██████╔╝██╔████╔██║",
    "    ██╔══╝  ██║██╔══██╗██║╚██╔╝██║",
    "    ██║     ██║██║  ██║██║ ╚═╝ ██║",
    "    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox.py firm flash"
    )
    
    # Serial Configuration
    parser.add_argument("--port", help="Serial port (e.g., /dev/ttyUSB0)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--list-ports", action="store_true", help="List available serial ports")
    
    # Actions
    parser.add_argument("--dump", action="store_true", help="Attempt to dump data from the port")
    parser.add_argument("--out", help="File to save the dumped firmware to")
    
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
    run_flash(args)

def run_flash(args):
    """
    Core logic for hardware security testing.
    """
    if args.list_ports:
        console.print("[*] Scanning for available serial ports...")
        ports = serial.tools.list_ports.comports()
        if not ports:
            console.print("[yellow][!] No serial ports found.[/yellow]")
            return
        for port in ports:
            console.print(f"  [+] {port.device} - {port.description}")
        return

    if not args.port:
        console.print("[bold red]Error:[/bold red] Please specify a port with --port or use --list-ports")
        return

    console.print(f"[*] Attemping connection to: [bold white]{args.port}[/bold white] @ {args.baud} baud")
    logger.info(f"FIRM Scan started: port={args.port}, baud={args.baud}")
    
    # 1. Serial Connection
    try:
        ser = serial.Serial(args.port, args.baud, timeout=2)
        console.print(f"[bold green][+] Connected to {args.port}![/bold green]")
        
        # 2. Dump (Simple loop)
        if args.dump:
            if not args.out:
                console.print("[bold red]Error:[/bold red] Please specify an output file with --out")
                ser.close()
                return

            console.print(f"[*] Dumping data to: [bold cyan]{args.out}[/bold cyan]... (Ctrl+C to stop)")
            with open(args.out, 'wb') as f:
                try:
                    while True:
                        data = ser.read(1024)
                        if data:
                            f.write(data)
                            console.print(f"  [>] Read {len(data)} bytes...", end='\r')
                        else:
                            break
                except KeyboardInterrupt:
                    console.print("\n[*] Dump stopped by user.")
            
            console.print(f"\n[bold green][+] Dump complete.[/bold green]")

        ser.close()
    except Exception as e:
        console.print(f"[bold red][!][/bold red] Serial connection failed: {e}")

    audit_log(logger, os.getlogin(), args.port, "firm/flash", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
