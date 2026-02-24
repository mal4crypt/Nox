import sys
import argparse
import os
import getpass
from datetime import datetime
from rich.console import Console
from utils.banner import print_nox_banner
from utils.logger import setup_logger, audit_log
from utils.formatter import format_output

console = Console()
logger = setup_logger("frizz_modx")

# --- Identity ---
TOOL_NAME = "FRIZZ"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Industrial & IoT Protocol Fuzzing Suite - Modbus TCP/RTU"

# --- Banner Config ---
BORDER = "dark_orange"
NAME_COLOR = "bold dark_orange"
FILL_COLOR = "orange3"
TAG_COLOR = "grey70"
FCHAR = "░"

ART_LINES = [
    "FFFFFFFFFFFFFFFFFFFFFFRRRRRRRRRRRRRRRRR   IIIIIIIIIIZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    "F::::::::::::::::::::FR::::::::::::::::R  I::::::::IZ:::::::::::::::::ZZ:::::::::::::::::Z",
    "F::::::::::::::::::::FR::::::RRRRRR:::::R I::::::::IZ:::::::::::::::::ZZ:::::::::::::::::Z",
    "FF::::::FFFFFFFFF::::FRR:::::R     R:::::RII::::::IIZ:::ZZZZZZZZ:::::Z Z:::ZZZZZZZZ:::::Z ",
    "  F:::::F       FFFFFF  R::::R     R:::::R  I::::I  ZZZZZ     Z:::::Z  ZZZZZ     Z:::::Z  ",
    "  F:::::F               R::::R     R:::::R  I::::I          Z:::::Z            Z:::::Z    ",
    "  F::::::FFFFFFFFFF     R::::RRRRRR:::::R   I::::I         Z:::::Z            Z:::::Z     ",
    "  F:::::::::::::::F     R:::::::::::::RR    I::::I        Z:::::Z            Z:::::Z      ",
    "  F:::::::::::::::F     R::::RRRRRR:::::R   I::::I       Z:::::Z            Z:::::Z       ",
    "  F::::::FFFFFFFFFF     R::::R     R:::::R  I::::I      Z:::::Z            Z:::::Z        ",
    "  F:::::F               R::::R     R:::::R  I::::I     Z:::::Z            Z:::::Z         ",
    "  F:::::F               R::::R     R:::::R  I::::I  ZZZ:::::Z     ZZZZZZZZ:::::Z     ZZZZZ",
    "FF:::::::FF           RR:::::R     R:::::RII::::::IIZ::::::ZZZZZZZZ:::ZZ::::::ZZZZZZZZ:::Z",
    "F::::::::FF           R::::::R     R:::::RI::::::::IZ:::::::::::::::::ZZ:::::::::::::::::Z",
    "F::::::::FF           R::::::R     R:::::RI::::::::IZ:::::::::::::::::ZZ:::::::::::::::::Z",
    "FFFFFFFFFFF           RRRRRRRR     RRRRRRRIIIIIIIIIIZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox.py frizz modx"
    )
    
    # Target Configuration
    parser.add_argument("--target", required=True, help="Target IP address or hostname")
    parser.add_argument("--port", type=int, default=502, help="Modbus port (default: 502)")
    parser.add_argument("--unit", type=int, default=1, help="Unit ID (default: 1)")
    
    # Fuzzing Configuration
    parser.add_argument("--type", choices=["tcp", "rtu"], default="tcp", help="Modbus type")
    parser.add_argument("--function", type=int, help="Specific function code to fuzz (e.g., 3, 6, 16)")
    parser.add_argument("--iterations", type=int, default=100, help="Number of fuzz iterations")
    parser.add_argument("--timeout", type=int, default=5, help="Network timeout")
    
    # Standards
    parser.add_argument("--output", choices=["json", "csv", "txt"], default="json", help="Output format")
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
    run_fuzzer(args)

import random
import time
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

def run_fuzzer(args):
    """
    Core fuzzing logic for Modbus protocol.
    """
    console.print(f"[*] Starting Modbus {args.type.upper()} fuzzer against {args.target}:{args.port}...")
    logger.info(f"Fuzzing session started: target={args.target}, port={args.port}, unit={args.unit}, iterations={args.iterations}")
    
    results = []
    client = ModbusTcpClient(args.target, port=args.port)
    
    try:
        if not client.connect():
            console.print(f"[bold red]Error:[/bold red] Could not connect to {args.target}:{args.port}")
            return

        for i in range(args.iterations):
            # Select function code to fuzz
            fn_code = args.function if args.function else random.choice([1, 2, 3, 4, 5, 6, 15, 16])
            
            # Generate fuzzed data
            address = random.randint(0, 65535)
            count = random.randint(1, 100)
            value = random.randint(0, 65535)
            
            console.print(f"[{i+1}/{args.iterations}] Fuzzing FN {fn_code} at ADDR {address}...")
            
            error_detected = None
            try:
                if fn_code == 1: # Read Coils
                    resp = client.read_coils(address, count, unit=args.unit)
                elif fn_code == 3: # Read Holding Registers
                    resp = client.read_holding_registers(address, count, unit=args.unit)
                elif fn_code == 6: # Write Single Register
                    resp = client.write_register(address, value, unit=args.unit)
                elif fn_code == 16: # Write Multiple Registers
                    resp = client.write_registers(address, [value] * (count % 10 + 1), unit=args.unit)
                else:
                    # Fallback for other codes
                    resp = client.execute(fn_code)
                
                if resp.isError():
                    error_detected = f"Modbus Error: {resp}"
                    
            except ModbusException as e:
                error_detected = f"Exception: {str(e)}"
            except Exception as e:
                error_detected = f"Unexpected Error: {str(e)}"

            if error_detected:
                logger.warning(f"Crash/Error at Iteration {i+1}: FN={fn_code} ADDR={address} Error={error_detected}")
                results.append({
                    "iteration": i + 1,
                    "function": fn_code,
                    "address": address,
                    "error": error_detected,
                    "timestamp": datetime.now().isoformat()
                })

            time.sleep(0.01) # Small delay to avoid flooding and losing state

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Fuzzing interrupted by user.[/bold yellow]")
    finally:
        client.close()

    # Audit log
    # Use getpass.getuser() which is safer in non-tty contexts than os.getlogin()
    audit_log(logger, getpass.getuser(), args.target, "frizz/modx", str(args), "SUCCESS")
    
    # Format & Output
    if results:
        console.print(f"\n[bold red]Detected {len(results)} potential vulnerabilities/errors:[/bold red]")
        formatted = format_output(results, args.output)
        console.print(formatted)
        
        # Save to logs/reports
        report_file = f"./logs/frizz_modx_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.output}"
        with open(report_file, 'w') as f:
            f.write(formatted)
        console.print(f"[*] Detailed report saved to [bold cyan]{report_file}[/bold cyan]")
    else:
        console.print("\n[bold green]Fuzzing complete. No crashes or Modbus errors detected.[/bold green]")

if __name__ == "__main__":
    main()
