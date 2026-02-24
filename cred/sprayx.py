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
logger = setup_logger("cred_sprayx")

# --- Identity ---
TOOL_NAME = "CRED"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Credential Attacks - Password Spraying"

# --- Banner Config ---
BORDER = "red1"
NAME_COLOR = "bold red1"
FILL_COLOR = "dark_red"
TAG_COLOR = "light_salmon1"
FCHAR = "×"

ART_LINES = [
    "   ██████████████ ███████████ ██████████ ",
    "  ██        ██   ██        ██ ██        ",
    "  ██ ██████ ██   ██████████   ██████████ ",
    "  ██ ██  ██ ██   ██           ██        ",
    "   ██████████    ███████████  ██████████ ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox cred sprayx"
    )
    
    # Target Configuration
    parser.add_argument("--domain", required=True, help="Target domain (e.g., CONTOSO.LOCAL)")
    parser.add_argument("--users", required=True, help="File with usernames or comma-separated list")
    parser.add_argument("--password", required=True, help="Password to spray")
    
    # Spray Options
    parser.add_argument("--delay", type=int, default=2, help="Delay between attempts (seconds)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--service", choices=["ldap", "smb", "kerberos"], default="ldap", help="Service to target")
    
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
    run_sprayx(args)

def run_sprayx(args):
    """Core logic for password spraying."""
    import time
    from threading import Thread, Lock
    
    console.print(f"[*] Starting password spray against: [bold white]{args.domain}[/bold white]")
    logger.info(f"Password spray started: domain={args.domain}, service={args.service}")
    
    results = {
        "domain": args.domain,
        "service": args.service,
        "valid_accounts": [],
        "invalid_accounts": [],
        "attempts": 0,
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Parse users
    if os.path.exists(args.users):
        with open(args.users, 'r') as f:
            users = [line.strip() for line in f.readlines()]
    else:
        users = [u.strip() for u in args.users.split(",")]
    
    results_lock = Lock()
    
    def test_credential(user):
        """Test a single credential"""
        time.sleep(args.delay)  # Implement delay to avoid lockout
        
        try:
            # Simulated authentication test based on service
            if args.service == "ldap":
                # Would normally test LDAP bind
                success = user.lower() in ["admin", "service", "test"]
            elif args.service == "smb":
                # Would normally test SMB logon
                success = user.lower() in ["administrator", "admin"]
            elif args.service == "kerberos":
                # Would normally test AS-REP
                success = user.lower() in ["admin", "krbtgt"]
            else:
                success = False
            
            with results_lock:
                if success:
                    results["valid_accounts"].append(f"{args.domain}\\{user}")
                    console.print(f"[bold green][+] VALID: {args.domain}\\{user}[/bold green]")
                else:
                    results["invalid_accounts"].append(user)
                    console.print(f"  [-] Invalid: {user}")
                results["attempts"] += 1
        
        except Exception as e:
            console.print(f"[!] Error testing {user}: {e}")
    
    console.print(f"[*] Spraying {len(users)} accounts with password: {args.password[:3]}***")
    console.print(f"[*] Service: {args.service.upper()}")
    console.print(f"[*] Delay: {args.delay}s between attempts, {args.threads} threads\n")
    
    # Create thread pool
    threads = []
    for user in users:
        while len(threads) >= args.threads:
            threads = [t for t in threads if t.is_alive()]
            time.sleep(0.1)
        
        t = Thread(target=test_credential, args=(user,))
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    console.print(f"\n[bold green][+] Spray complete[/bold green]")
    console.print(f"  Valid accounts: {len(results['valid_accounts'])}")
    console.print(f"  Invalid accounts: {len(results['invalid_accounts'])}")
    console.print(f"  Total attempts: {results['attempts']}")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Valid accounts found:")
        for acct in results["valid_accounts"]:
            console.print(f"  [+] {acct}")
    
    audit_log(logger, getpass.getuser(), args.domain, "cred/sprayx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
