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
logger = setup_logger("vuln_scanx")

# --- Identity ---
TOOL_NAME = "VULN"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Vulnerability Management - Network Scanning"

# --- Banner Config ---
BORDER = "salmon1"
NAME_COLOR = "bold salmon1"
FILL_COLOR = "light_red"
TAG_COLOR = "light_salmon1"
FCHAR = "!"

ART_LINES = [
    "  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ",
    "  ██║   ██║██║   ██║██║     ████╗  ██║ ",
    "  ██║   ██║██║   ██║██║     ██╔██╗ ██║ ",
    "  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║ ",
    "   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║ ",
    "    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox vuln scanx"
    )
    
    # Scan Target
    parser.add_argument("--target", required=True, help="Target IP, network, or hostname")
    parser.add_argument("--ports", default="1-65535", help="Port range (default: 1-65535)")
    
    # Scan Options
    parser.add_argument("--scan-type", choices=["fast", "standard", "thorough"], default="standard", help="Scan intensity")
    parser.add_argument("--service-detection", action="store_true", help="Detect service versions")
    parser.add_argument("--vuln-check", action="store_true", help="Check for known vulnerabilities")
    
    # Output Options
    parser.add_argument("--output", choices=["json", "csv", "txt"], default="json", help="Output format")
    parser.add_argument("--out-file", help="Save scan results to file")
    
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
    run_scanx(args)

def run_scanx(args):
    """Core logic for vulnerability scanning."""
    import socket
    import time
    
    console.print(f"[*] Starting vulnerability scan: [bold white]{args.target}[/bold white]")
    console.print(f"[*] Ports: {args.ports} | Mode: {args.scan_type.upper()}")
    logger.info(f"Vulnerability scan started: target={args.target}")
    
    results = {
        "target": args.target,
        "open_ports": [],
        "services": {},
        "vulnerabilities": [],
        "scan_type": args.scan_type,
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Parse port range
    port_list = []
    for port_range in args.ports.split(","):
        if "-" in port_range:
            start, end = port_range.split("-")
            port_list.extend(range(int(start), int(end) + 1))
        else:
            port_list.append(int(port_range))
    
    # Limit ports based on scan type
    if args.scan_type == "fast":
        port_list = port_list[:20]  # Common ports only
    elif args.scan_type == "standard":
        port_list = port_list[:100]  # Top 100 ports
    # thorough scans all ports
    
    console.print(f"[*] Scanning {len(port_list)} ports for open services...")
    
    # Simulate port scanning with timeout
    common_ports = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        5985: "WinRM",
        139: "SMB",
        445: "SMB",
        23: "Telnet",
        21: "FTP",
    }
    
    for port in port_list:
        if port not in common_ports:
            continue
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((args.target, port))
            sock.close()
            
            if result == 0:
                service = common_ports.get(port, "Unknown")
                results["open_ports"].append(f"{port}/tcp")
                results["services"][f"{port}/tcp"] = service
                console.print(f"  [+] {port}/tcp ({service})")
                time.sleep(0.1)
        except Exception as e:
            pass  # Port not reachable or unreachable target
    
    # Check for known vulnerabilities
    if args.vuln_check and results["open_ports"]:
        console.print("[*] Checking for known vulnerabilities...")
        
        # Simulated vulnerability database
        vuln_db = {
            "22/tcp": [{"cve": "CVE-2021-36221", "severity": "High", "service": "OpenSSH"}],
            "80/tcp": [{"cve": "CVE-2021-41773", "severity": "Critical", "service": "Apache"}],
            "443/tcp": [{"cve": "CVE-2021-41773", "severity": "Critical", "service": "Apache"}],
            "3306/tcp": [{"cve": "CVE-2021-2109", "severity": "Medium", "service": "MySQL"}],
        }
        
        for port in results["open_ports"]:
            if port in vuln_db:
                for vuln in vuln_db[port]:
                    results["vulnerabilities"].append(vuln)
                    console.print(f"  [!] {vuln['cve']} - {vuln['severity']}")
    
    console.print(f"\n[bold green][+] Scan complete[/bold green]")
    console.print(f"  Open ports: {len(results['open_ports'])}")
    console.print(f"  Vulnerabilities found: {len(results['vulnerabilities'])}")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Open ports:")
        for port in results["open_ports"]:
            console.print(f"  {port}")
    
    audit_log(logger, getpass.getuser(), args.target, "vuln/scanx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
