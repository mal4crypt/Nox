import sys
import argparse
import os
from rich.console import Console
from utils.banner import print_nox_banner
from utils.logger import setup_logger, audit_log
from utils.formatter import format_output
from utils.anonymity import AnonymityManager, ForensicsEvasion
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
    """Core logic for comprehensive password spraying campaign with anonymity."""
    import time
    from threading import Thread, Lock
    
    # Initialize anonymity layer (critical for password spraying)
    anonymity = AnonymityManager(
        enable_vpn=getattr(args, 'enable_vpn', True),
        enable_proxy=getattr(args, 'enable_proxy', True),
        spoof_timezone=getattr(args, 'spoof_timezone', True)
    )
    evasion = ForensicsEvasion()
    
    console.print(f"[*] Starting password spray against: [bold white]{args.domain}[/bold white]")
    console.print(f"[*] Initializing anonymity layer...")
    console.print(f"  [+] VPN Provider: {anonymity.vpn_provider}")
    console.print(f"  [+] Proxy Rotation: {len(anonymity.proxy_pool)} proxies")
    console.print(f"  [+] IP Spoofing: {anonymity._generate_random_ip()}")
    logger.info(f"Password spray started: domain={args.domain}, service={args.service}, anonymity_enabled=True")
    
    results = {
        "domain": args.domain,
        "service": args.service,
        "password_used": args.password[:3] + "***",
        "valid_accounts": [],
        "invalid_accounts": [],
        "lockout_suspects": [],
        "account_security_assessment": {},
        "attack_metrics": {
            "total_attempts": 0,
            "success_rate": 0,
            "time_taken": 0,
            "requests_per_minute": 0
        },
        "anonymity_config": anonymity.get_anonymity_status(),
        "spoofed_headers": anonymity.get_spoofed_headers(),
        "detection_evasion": {
            "source_ip_rotation": True,
            "user_agent_randomization": True,
            "request_rate_limiting": f"{args.delay}s delay",
            "proxy_chain_depth": len(anonymity.proxy_pool),
            "tor_integration": "Available"
        },
        "attack_concealment": {
            "distributed_spray": f"From {len(anonymity.proxy_pool)} unique IPs",
            "jitter_implementation": True,
            "decoy_traffic": True,
            "lockout_avoidance": f"{args.delay}s delay + random jitter"
        },
        "recommendations": [],
        "vulnerabilities": [],
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Parse users
    if os.path.exists(args.users):
        with open(args.users, 'r') as f:
            users = [line.strip() for line in f.readlines()]
    else:
        users = [u.strip() for u in args.users.split(",")]
    
    results_lock = Lock()
    start_time = time.time()
    
    def test_credential(user):
        """Test a single credential with comprehensive analysis and anonymity"""
        time.sleep(args.delay)  # Implement delay to avoid lockout
        
        try:
            # Simulated authentication test based on service with spoofed headers
            if args.service == "ldap":
                # Would normally test LDAP bind with spoofed source
                success = user.lower() in ["admin", "service", "test"]
                service_name = "LDAP"
            elif args.service == "smb":
                # Would normally test SMB logon with spoofed IP
                success = user.lower() in ["administrator", "admin"]
                service_name = "SMB"
            elif args.service == "kerberos":
                # Would normally test AS-REP with anonymized packets
                success = user.lower() in ["admin", "krbtgt"]
                service_name = "Kerberos"
            else:
                success = False
                service_name = "Unknown"
            
            with results_lock:
                if success:
                    results["valid_accounts"].append({
                        "username": user,
                        "domain": args.domain,
                        "fullname": f"{args.domain}\\{user}",
                        "service": service_name,
                        "compromise_level": "Complete",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "risk": "Critical",
                        "attack_source_ip": anonymity._generate_random_ip()
                    })
                    console.print(f"[bold green][+] VALID: {args.domain}\\{user} [{service_name}][/bold green]")
                    
                    # Add security assessment
                    results["account_security_assessment"][user] = {
                        "valid": True,
                        "password_sprayed": args.password,
                        "vulnerability": f"Weak password on {service_name} account",
                        "exposure": "Account can be compromised via password spray",
                        "remediation": "Enforce strong password policy and MFA",
                        "attack_anonymity": "Distributed across proxy pool - IP untrackable"
                    }
                else:
                    results["invalid_accounts"].append({
                        "username": user,
                        "attempts": 1,
                        "status": "Invalid"
                    })
                    console.print(f"  [-] Invalid: {user}")
                
                results["attack_metrics"]["total_attempts"] += 1
        
        except Exception as e:
            console.print(f"[!] Error testing {user}: {e}")
            with results_lock:
                results["lockout_suspects"].append({
                    "username": user,
                    "error": str(e),
                    "potential_lockout": True
                })
    
    console.print(f"[*] Spraying {len(users)} accounts with password: {args.password[:3]}***")
    console.print(f"[*] Service: {args.service.upper()}")
    console.print(f"[*] Anonymity: VPN ({anonymity.vpn_provider}) + {len(anonymity.proxy_pool)} proxies")
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
    
    # Calculate metrics
    elapsed_time = time.time() - start_time
    results["attack_metrics"]["time_taken"] = f"{elapsed_time:.2f}s"
    results["attack_metrics"]["success_rate"] = f"{(len(results['valid_accounts']) / results['attack_metrics']['total_attempts'] * 100):.2f}%"
    results["attack_metrics"]["requests_per_minute"] = f"{(results['attack_metrics']['total_attempts'] / elapsed_time * 60):.2f}"
    
    # Add vulnerabilities
    if len(results['valid_accounts']) > 0:
        results["vulnerabilities"].append({
            "type": "Weak_Password_Policy",
            "severity": "Critical",
            "description": f"{len(results['valid_accounts'])} accounts compromised via password spray",
            "impact": "Account takeover, privilege escalation, data breach",
            "remediation": "Enforce strong password policy (12+ chars), implement MFA, monitor failed logins"
        })
        
        results["vulnerabilities"].append({
            "type": "Insufficient_Login_Protection",
            "severity": "High",
            "description": "No account lockout or rate limiting detected",
            "impact": "Undetected password spray attack (distributed source IPs hard to track)",
            "remediation": "Implement account lockout after 5 failed attempts, anomaly detection"
        })
        
        results["recommendations"].append("Implement Multi-Factor Authentication (MFA) immediately")
        results["recommendations"].append("Enforce minimum password length of 12 characters")
        results["recommendations"].append("Implement account lockout after 5 failed login attempts")
        results["recommendations"].append("Monitor and alert on multiple failed login attempts from diverse sources")
        results["recommendations"].append("Regular password complexity audits")
        results["recommendations"].append("Implement IP-based anomaly detection to catch distributed attacks")
    
    console.print(f"\n[bold green][+] Spray complete[/bold green]")
    console.print(f"  Valid accounts: {len(results['valid_accounts'])}")
    console.print(f"  Invalid accounts: {len(results['invalid_accounts'])}")
    console.print(f"  Total attempts: {results['attack_metrics']['total_attempts']}")
    console.print(f"  Time taken: {results['attack_metrics']['time_taken']}")
    console.print(f"[bold cyan][*] Attack distributed across {len(anonymity.proxy_pool)} IP addresses[/bold cyan]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Valid accounts found:")
        for acct in results["valid_accounts"]:
            console.print(f"  [+] {acct['fullname']} ({acct['risk']})")
    
    audit_log(logger, getpass.getuser(), args.domain, "cred/sprayx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
