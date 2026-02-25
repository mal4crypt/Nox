import sys
import argparse
import os
import requests
import whois
import dns.resolver
import socket
import ssl
from rich.console import Console
from datetime import datetime
from utils.banner import print_nox_banner
from utils.logger import setup_logger, audit_log
from utils.formatter import format_output

console = Console()
logger = setup_logger("spekt_intel")

# --- Identity ---
TOOL_NAME = "SPEKT"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "OSINT Automation & Intelligence Gathering"

# --- Banner Config ---
BORDER = "spring_green3"
NAME_COLOR = "bold spring_green3"
FILL_COLOR = "medium_spring_green"
TAG_COLOR = "aquamarine1"
FCHAR = "─"

ART_LINES = [
    " ░▒▓███████▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░ ",
    "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
    "░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
    " ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░   ░▒▓█▓▒░     ",
    "       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
    "       ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
    "░▒▓███████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     ",
]

def main():
    parser = argparse.ArgumentParser(
        description=TOOL_DESCRIPTION,
        prog="nox.py spekt intel"
    )
    
    # Target Configuration
    parser.add_argument("--target", required=True, help="Target domain or IP address")
    
    # OSINT Options
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--geo", action="store_true", help="Perform GeoIP lookup (for IPs)")
    parser.add_argument("--all", action="store_true", help="Perform all basic intelligence tasks")
    
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
    run_osint(args)

def get_ssl_cert_info(target):
    """Extract SSL certificate information"""
    try:
        hostname = target.split('/')[0]
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((hostname, 443))
        ssock = context.wrap_socket(sock, server_hostname=hostname)
        cert = ssock.getpeercert()
        ssock.close()
        return {
            "subject": str(cert.get('subject', 'N/A')),
            "issuer": str(cert.get('issuer', 'N/A')),
            "version": cert.get('version'),
            "notBefore": cert.get('notBefore'),
            "notAfter": cert.get('notAfter')
        }
    except Exception as e:
        return {}

def get_http_headers(target):
    """Extract HTTP header information"""
    try:
        url = f"http://{target}" if not target.startswith('http') else target
        response = requests.head(url, timeout=5, allow_redirects=True)
        headers = dict(response.headers)
        return {
            "server": headers.get('Server', 'Unknown'),
            "x_powered_by": headers.get('X-Powered-By', 'N/A'),
            "x_aspnet_version": headers.get('X-AspNet-Version', 'N/A'),
            "content_type": headers.get('Content-Type', 'N/A'),
            "cookies": headers.get('Set-Cookie', 'N/A'),
            "csp": headers.get('Content-Security-Policy', 'N/A'),
            "cache_control": headers.get('Cache-Control', 'N/A')
        }
    except Exception as e:
        return {"error": str(e)}

def get_ip_info(target):
    """Get IP and geolocation information"""
    try:
        try:
            ip = socket.gethostbyname(target)
        except:
            ip = target
        
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        if response.status_code == 200:
            geo = response.json()
            return {
                "ip": geo.get('query'),
                "isp": geo.get('isp'),
                "organization": geo.get('org'),
                "country": geo.get('country'),
                "region": geo.get('regionName'),
                "city": geo.get('city'),
                "latitude": geo.get('lat'),
                "longitude": geo.get('lon'),
                "timezone": geo.get('timezone')
            }
    except:
        pass
    return {}

def run_osint(args):
    """
    Core logic for OSINT gathering with comprehensive reconnaissance.
    """
    target = args.target
    console.print(f"[*] Gathering intelligence on: [bold white]{target}[/bold white]...")
    logger.info(f"OSINT Scan started: target={target}")
    
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "dns": {},
        "whois": {},
        "geo_ip": {},
        "http_headers": {},
        "ssl_certificate": {},
        "subdomains": {},
        "network": {},
        "security": {}
    }

    # 1. DNS Recon
    if args.dns or args.all:
        console.print("[*] Performing DNS reconnaissance...")
        try:
            records = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
            for record in records:
                try:
                    answers = dns.resolver.resolve(target, record)
                    results["dns"][record] = [str(rdata) for rdata in answers]
                    console.print(f"  [+] {record} records found: {len(answers)}")
                except:
                    pass
        except Exception as e:
            console.print(f"[bold red][!][/bold red] DNS Recon failed: {e}")

    # 2. WHOIS
    if args.whois or args.all:
        console.print("[*] Retrieving WHOIS information...")
        try:
            w = whois.whois(target)
            results["whois"] = {
                "registrar": str(w.registrar),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "last_updated": str(w.updated_date),
                "name_servers": w.name_servers if w.name_servers else [],
                "registrant_name": str(w.registrant_name) if hasattr(w, 'registrant_name') else 'N/A',
                "registrant_org": str(w.registrant_org) if hasattr(w, 'registrant_org') else 'N/A',
                "registrant_country": str(w.registrant_country) if hasattr(w, 'registrant_country') else 'N/A'
            }
            console.print("  [+] WHOIS records retrieved.")
        except Exception as e:
            console.print(f"[bold red][!][/bold red] WHOIS Lookup failed: {e}")

    # 3. GeoIP & IP Information
    if args.geo or args.all:
        console.print("[*] Performing GeoIP and IP intelligence...")
        geo = get_ip_info(target)
        results["geo_ip"] = geo
        if geo and "error" not in geo:
            console.print(f"  [+] IP: {geo.get('ip')}, Location: {geo.get('city')}, {geo.get('country')}")
            console.print(f"  [+] ISP: {geo.get('isp')}, Organization: {geo.get('organization')}")

    # 4. HTTP Headers & Technology Fingerprinting
    if args.all:
        console.print("[*] Analyzing HTTP headers and technologies...")
        headers = get_http_headers(target)
        results["http_headers"] = headers
        if "error" not in headers:
            console.print(f"  [+] Server: {headers.get('server')}")
            console.print(f"  [+] Powered By: {headers.get('x_powered_by')}")

    # 5. SSL Certificate Information
    if args.all:
        console.print("[*] Extracting SSL certificate information...")
        cert = get_ssl_cert_info(target)
        results["ssl_certificate"] = cert
        if "error" not in cert:
            console.print(f"  [+] Certificate Issuer: {cert.get('issuer', {}).get('commonName')}")
            console.print(f"  [+] Valid Until: {cert.get('notAfter')}")

    # 6. Security Headers Check
    if args.all:
        console.print("[*] Checking security configurations...")
        headers = get_http_headers(target)
        security = {
            "has_csp": "csp" in headers and headers["csp"] != 'N/A',
            "has_hsts": "strict-transport-security" in str(headers).lower(),
            "has_x_frame_options": "x-frame-options" in str(headers).lower(),
            "server_disclosed": headers.get('server') != 'N/A'
        }
        results["security"] = security
        console.print(f"  [+] CSP: {security['has_csp']}, HSTS: {security['has_hsts']}, X-Frame: {security['has_x_frame_options']}")

    try:
        audit_log(logger, os.getlogin(), target, "spekt/intel", str(args), "SUCCESS")
    except:
        logger.info(f"OSINT completed for {target}")
    
    # Export
    formatted = format_output(results, args.output)
    console.print("\n[bold cyan]Intelligence Report:[/bold cyan]")
    console.print(formatted)
    
    report_file = f"./logs/spekt_intel_{target.replace('.','_').replace('/','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.output}"
    os.makedirs("./logs", exist_ok=True)
    with open(report_file, 'w') as f:
        f.write(formatted)
    console.print(f"[*] Intelligence results saved to [bold cyan]{report_file}[/bold cyan]")

if __name__ == "__main__":
    main()
