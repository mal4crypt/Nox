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
logger = setup_logger("recon_subx")

# --- Identity ---
TOOL_NAME = "RECON"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Reconnaissance & Active Discovery - Subdomain Enumeration"

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
        prog="nox recon subx"
    )
    
    # Target Configuration
    parser.add_argument("--domain", required=True, help="Target domain to enumerate")
    
    # Enumeration Options
    parser.add_argument("--wordlist", help="Custom wordlist for subdomain brute-force")
    parser.add_argument("--all", action="store_true", help="Use all enumeration methods")
    parser.add_argument("--passive", action="store_true", help="Passive enumeration only (DNS/WHOIS)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    
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
    run_subx(args)

def run_subx(args):
    """Core logic for comprehensive subdomain enumeration."""
    import socket
    import dns.resolver
    import requests
    
    console.print(f"[*] Starting comprehensive subdomain enumeration for: [bold white]{args.domain}[/bold white]")
    logger.info(f"Subdomain enum started: domain={args.domain}")
    
    results = {
        "domain": args.domain,
        "subdomains_found": [],
        "dns_records": {
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "ns_records": [],
            "cname_records": []
        },
        "ips": {},
        "http_status": {},
        "vulnerability_assessment": [],
        "statistics": {
            "total_subdomains": 0,
            "live_services": 0,
            "web_services": 0
        },
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Extended subdomain wordlist
    common_subs = [
        "www", "mail", "ftp", "admin", "api", "staging", "dev", "test",
        "blog", "shop", "store", "app", "mobile", "m", "webmail", "smtp",
        "imap", "pop", "ns1", "ns2", "vpn", "server", "database", "db",
        "backup", "git", "jenkins", "jira", "confluence", "gitlab",
        "internal", "private", "secure", "local", "old", "legacy",
        "temp", "tmp", "demo", "static", "media", "cdn", "download",
        "assets", "files", "documents", "support", "help", "docs"
    ]
    
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist, 'r') as f:
            common_subs = [line.strip() for line in f.readlines() if line.strip()]
        console.print(f"[*] Loaded {len(common_subs)} subdomains from wordlist")
    
    console.print("[*] Performing DNS lookups and service enumeration...")
    found_count = 0
    live_count = 0
    
    for sub in common_subs:
        try:
            full_domain = f"{sub}.{args.domain}"
            # Try to resolve the subdomain
            answers = dns.resolver.resolve(full_domain, 'A')
            
            for rdata in answers:
                ip = str(rdata)
                results["subdomains_found"].append({
                    "subdomain": full_domain,
                    "ip": ip,
                    "resolved": True
                })
                results["ips"][full_domain] = ip
                results["dns_records"]["a_records"].append({
                    "domain": full_domain,
                    "ip": ip,
                    "ttl": "3600"
                })
                found_count += 1
                live_count += 1
                
                # Check HTTP/HTTPS service
                for protocol in ["http", "https"]:
                    try:
                        url = f"{protocol}://{full_domain}"
                        response = requests.head(url, timeout=3, verify=False)
                        results["http_status"][full_domain] = {
                            "protocol": protocol,
                            "status_code": response.status_code,
                            "server": response.headers.get('Server', 'Unknown'),
                            "title": response.headers.get('X-Frame-Options', 'Not set')
                        }
                        results["statistics"]["web_services"] += 1
                        break
                    except:
                        pass
                
                console.print(f"  [+] {full_domain:30} → {ip}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Subdomain not found
        except Exception as e:
            pass
    
    # Get additional DNS records
    console.print("[*] Enumerating additional DNS records...")
    try:
        # MX Records
        mx = dns.resolver.resolve(args.domain, 'MX')
        for record in mx:
            mx_host = str(record.exchange)
            results["dns_records"]["mx_records"].append({
                "priority": record.preference,
                "mail_server": mx_host
            })
            console.print(f"  [+] MX: {mx_host} (Priority: {record.preference})")
    except:
        pass
    
    try:
        # TXT Records
        txt = dns.resolver.resolve(args.domain, 'TXT')
        for record in txt:
            txt_value = str(record)
            results["dns_records"]["txt_records"].append({
                "value": txt_value,
                "type": "TXT"
            })
            console.print(f"  [+] TXT: {txt_value[:50]}...")
    except:
        pass
    
    try:
        # NS Records
        ns = dns.resolver.resolve(args.domain, 'NS')
        for record in ns:
            ns_host = str(record)
            results["dns_records"]["ns_records"].append({
                "nameserver": ns_host
            })
            console.print(f"  [+] NS: {ns_host}")
    except:
        pass
    
    # Vulnerability Assessment
    if found_count > 0:
        results["vulnerability_assessment"].append({
            "finding": "Subdomain Discovery",
            "severity": "Medium",
            "description": f"Found {found_count} subdomains, potential attack surface expansion",
            "remediation": "Document all subdomains and ensure they are protected"
        })
    
    if any("admin" in sub for sub in [s["subdomain"] for s in results["subdomains_found"]]):
        results["vulnerability_assessment"].append({
            "finding": "Admin Panel Detected",
            "severity": "High",
            "description": "Admin/management panel identified in subdomain enumeration",
            "remediation": "Restrict admin panel access, implement strong authentication"
        })
    
    # Statistics
    results["statistics"]["total_subdomains"] = found_count
    results["statistics"]["live_services"] = live_count
    
    console.print(f"\n[bold green][+] Enumeration complete: {found_count} subdomains found, {live_count} live[/bold green]")
    
    if args.out_file:
        format_output(results, args.output, args.out_file)
        console.print(f"[bold cyan]Results saved to: {args.out_file}[/bold cyan]")
    else:
        console.print("[*] Results:")
        import json
        console.print(json.dumps(results, indent=2))
    
    audit_log(logger, getpass.getuser(), args.domain, "recon/subx", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
