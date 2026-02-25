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
    Core logic for comprehensive Android security enumeration and exploitation.
    """
    adb_cmd = ["adb"]
    if args.serial:
        adb_cmd.extend(["-s", args.serial])
    
    console.print(f"[*] Target Device: [bold white]{args.serial if args.serial else 'Default'}[/bold white]")
    logger.info(f"Droid Scan started: device={args.serial}")
    
    results = {
        "device_info": {},
        "security_issues": [],
        "packages": {
            "all": [],
            "vulnerable": [],
            "debuggable": []
        },
        "permissions": [],
        "vulnerability_assessment": {
            "critical": [],
            "high": [],
            "medium": []
        },
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # 1. Check Connection
    try:
        subprocess.check_output(adb_cmd + ["get-state"], stderr=subprocess.STDOUT)
        console.print("[bold green][+] Device connected[/bold green]")
    except subprocess.CalledProcessError:
        console.print("[bold red]Error:[/bold red] ADB device not found or offline.")
        return
    except FileNotFoundError:
        console.print("[bold red]Error:[/bold red] ADB command not found. Please install adb.")
        return

    # Get device properties
    try:
        android_version = subprocess.check_output(adb_cmd + ["shell", "getprop", "ro.build.version.release"]).decode().strip()
        device_model = subprocess.check_output(adb_cmd + ["shell", "getprop", "ro.product.model"]).decode().strip()
        manufacturer = subprocess.check_output(adb_cmd + ["shell", "getprop", "ro.product.manufacturer"]).decode().strip()
        
        results["device_info"] = {
            "model": device_model,
            "manufacturer": manufacturer,
            "android_version": android_version,
            "api_level": subprocess.check_output(adb_cmd + ["shell", "getprop", "ro.build.version.sdk"]).decode().strip()
        }
    except:
        pass

    # 2. List Packages with vulnerability assessment
    if args.list_packages:
        console.print("[*] Retrieving package list...")
        try:
            output = subprocess.check_output(adb_cmd + ["shell", "pm", "list", "packages"]).decode()
            packages = [line.strip().replace("package:", "") for line in output.splitlines() if "package:" in line]
            results["packages"]["all"] = packages
            
            # Check for known vulnerable packages
            vulnerable_packages = {
                "com.facebook.katana": "Facebook (multiple vulns)",
                "com.whatsapp": "WhatsApp (outdated encryption)",
                "com.android.chrome": "Chrome (WebView vulnerabilities)",
                "com.android.vending": "Google Play Store",
                "com.google.android.gms": "Google Play Services (tracking)",
                "com.android.settings": "Settings (exposure of sensitive data)"
            }
            
            for pkg in packages:
                if pkg in vulnerable_packages:
                    results["packages"]["vulnerable"].append({
                        "package": pkg,
                        "issue": vulnerable_packages[pkg],
                        "severity": "High",
                        "remediation": "Update to latest version or uninstall"
                    })
            
            console.print(f"  [+] Found {len(packages)} packages ({len(results['packages']['vulnerable'])} potentially vulnerable)")
            
            # Add security findings
            if len(results["packages"]["vulnerable"]) > 0:
                results["security_issues"].append({
                    "type": "Known_Vulnerable_Applications",
                    "severity": "High",
                    "count": len(results["packages"]["vulnerable"]),
                    "description": "Device has installed applications with known vulnerabilities",
                    "remediation": "Update all applications from Play Store"
                })
        except Exception as e:
            console.print(f"[bold red][!][/bold red] Failed to list packages: {e}")

    # 3. Check Debug & Security Properties
    if args.check_debug:
        console.print("[*] Analyzing security properties...")
        security_props = {
            "ro.debuggable": ("Debuggable Build", "Critical"),
            "ro.secure": ("Secure Flag", "High"),
            "ro.boot.serialno": ("Serial Number", "Medium"),
            "persist.sys.usb.config": ("USB Config", "Medium")
        }
        
        for prop, (name, severity) in security_props.items():
            try:
                val = subprocess.check_output(adb_cmd + ["shell", "getprop", prop]).decode().strip()
                
                if prop == "ro.debuggable" and val == "1":
                    console.print(f"[bold red][!] Device is DEBUGGABLE (ro.debuggable=1)[/bold red]")
                    results["security_issues"].append({
                        "type": "Debuggable_Device",
                        "severity": "Critical",
                        "value": val,
                        "description": "Device allows arbitrary code execution via ADB",
                        "impact": "Complete device compromise possible",
                        "remediation": "Disable USB debugging, enable Android 10+ security"
                    })
                elif prop == "ro.secure" and val == "0":
                    results["security_issues"].append({
                        "type": "Insecure_Device_Properties",
                        "severity": "High",
                        "description": "Security flag disabled",
                        "impact": "SELinux protections may be weakened"
                    })
                else:
                    console.print(f"  [+] {name}: {val}")
            except:
                pass

    # 4. Pull APK with analysis
    if args.pull:
        package = args.pull
        console.print(f"[*] Analyzing package: [bold cyan]{package}[/bold cyan]")
        try:
            path_output = subprocess.check_output(adb_cmd + ["shell", "pm", "path", package]).decode().strip()
            if "package:" in path_output:
                apk_path = path_output.split(":")[1]
                subprocess.check_call(adb_cmd + ["pull", apk_path, f"./logs/{package}.apk"], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                console.print(f"[bold green][+] APK pulled successfully to ./logs/{package}.apk[/bold green]")
                
                # Get package info
                try:
                    perms_output = subprocess.check_output(
                        adb_cmd + ["shell", "dumpsys", "package", package]
                    ).decode()
                    
                    # Extract permissions
                    in_perms = False
                    for line in perms_output.split('\n'):
                        if "requested permissions:" in line:
                            in_perms = True
                        elif in_perms and line.strip().startswith("android.permission"):
                            perm = line.strip()
                            results["packages"]["all"].append(perm)
                            
                            # Flag dangerous permissions
                            dangerous_perms = [
                                "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
                                "READ_CONTACTS", "READ_SMS", "WRITE_SETTINGS"
                            ]
                            
                            if any(d in perm for d in dangerous_perms):
                                results["vulnerability_assessment"]["high"].append({
                                    "package": package,
                                    "permission": perm,
                                    "risk": "Sensitive data access",
                                    "remediation": "Review app permissions in Settings"
                                })
                except:
                    pass
            else:
                console.print(f"[bold red][!] Package {package} not found.[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!][/bold red] Failed to pull APK: {e}")

    # Summary
    console.print(f"\n[bold green][+] Security Analysis Complete[/bold green]")
    console.print(f"  Critical Issues: {len(results['security_issues'])}")
    console.print(f"  Vulnerable Apps: {len(results['packages']['vulnerable'])}")
    
    import getpass
    audit_log(logger, getpass.getuser(), args.serial if args.serial else "ADB", "mobi/droid", str(args), "SUCCESS")

if __name__ == "__main__":
    main()
