#!/usr/bin/env python3
"""
NOX Tool Registry & Relationship Database
Maps all Nox suites/modules to external tools and defines tool relationships
for cross-referencing and enhanced integration.
"""

# Tool relationships organized by security domain
TOOL_REGISTRY = {
    # OFFENSIVE SECURITY TOOLS
    "recon": {
        "modules": ["subx"],
        "category": "Offensive Security",
        "description": "Reconnaissance and enumeration",
        "related_tools": {
            "subdomain_enumeration": [
                "amass", "subfinder", "assetfinder", "sublist3r", 
                "dnsx", "fierce", "crt.sh", "altdns", "knockpy"
            ],
        },
        "external_tools": {
            "amass": "Subdomain enumeration with intel aggregation",
            "subfinder": "Fast subdomain enumeration",
            "assetfinder": "Find domains and subdomains",
            "sublist3r": "Web-based subdomain enumeration",
            "dnsx": "DNS query/bruteforce",
            "fierce": "Domain/network reconnaissance",
        }
    },
    
    "webpwn": {
        "modules": ["sqlix"],
        "category": "Offensive Security",
        "description": "Web application exploitation",
        "related_tools": {
            "sql_injection": [
                "sqlmap", "ghauri", "havij", "sqlninja", 
                "bbqsql", "ems", "nosuqli"
            ],
        },
        "external_tools": {
            "sqlmap": "Automated SQL injection testing",
            "ghauri": "Advanced SQL injection detection",
            "havij": "GUI-based SQL injection tool (legacy)",
            "sqlninja": "SQL injection fingerprinting",
            "nuclei": "Template-based vulnerability scanner",
        }
    },
    
    "cred": {
        "modules": ["sprayx"],
        "category": "Offensive Security",
        "description": "Credential attacks and access testing",
        "related_tools": {
            "password_spraying": [
                "spray", "kerbrute", "crackmapexec", 
                "ruler", "o365spray", "adfs-spray"
            ],
        },
        "external_tools": {
            "spray": "Password spray against AD",
            "kerbrute": "Kerberos user enumeration",
            "crackmapexec": "Network post-exploitation",
            "ruler": "Outlook/Exchange exploitation",
            "o365spray": "Office 365 credential spray",
        }
    },
    
    "netpwn": {
        "modules": ["vlanx"],
        "category": "Offensive Security",
        "description": "Network and VLAN attacks",
        "related_tools": {
            "network_attacks": [
                "yersinia", "scapy", "frogger", "dtp-attack",
                "responder", "mitm6", "dhcpig"
            ],
        },
        "external_tools": {
            "yersinia": "VLAN hopping and network attacks",
            "scapy": "Network packet manipulation",
            "frogger": "VLAN enumeration and hopping",
            "responder": "LLMNR/NBNS/mDNS spoofing",
            "mitm6": "IPv6 attack framework",
        }
    },
    
    "phish": {
        "modules": ["campx"],
        "category": "Offensive Security",
        "description": "Phishing campaign management",
        "related_tools": {
            "phishing_campaigns": [
                "gophish", "setoolkit", "evilginx2", 
                "zphisher", "sendgrid-api", "owa-phish"
            ],
        },
        "external_tools": {
            "gophish": "Phishing framework with real-time tracking",
            "setoolkit": "Social engineering toolkit",
            "evilginx2": "Credential harvesting proxy",
            "zphisher": "Automated phishing page generator",
        }
    },
    
    "c2": {
        "modules": ["server"],
        "category": "Offensive Security",
        "description": "Command and Control infrastructure",
        "related_tools": {
            "command_control": [
                "metasploit", "sliver", "havoc", "covenant",
                "empire", "pupy", "mythic", "faction"
            ],
        },
        "external_tools": {
            "metasploit": "Full-featured exploitation framework",
            "sliver": "Implant-based C2 (Cobalt Strike alternative)",
            "havoc": "Modern C2 framework",
            "covenant": ".NET-based C2 framework",
            "empire": "PowerShell-based C2",
        }
    },
    
    "pivot": {
        "modules": ["sockx"],
        "category": "Offensive Security",
        "description": "Lateral movement and pivoting",
        "related_tools": {
            "lateral_movement": [
                "proxychains", "chisel", "ligolo-ng", 
                "sshuttle", "redsocks", "localproxy"
            ],
        },
        "external_tools": {
            "proxychains": "Force connections through proxies",
            "chisel": "Fast TCP/UDP tunnel over HTTP",
            "ligolo-ng": "Powerful tunneling/pivoting tool",
            "sshuttle": "VPN-like tunnel via SSH",
            "redsocks": "Transparent socks redirector",
        }
    },
    
    # DEFENSIVE SECURITY TOOLS
    "blue": {
        "modules": ["memx"],
        "category": "Defensive Security",
        "description": "Memory forensics and analysis",
        "related_tools": {
            "memory_forensics": [
                "volatility3", "volatility2", "rekall", 
                "lime", "dumpit", "memoryze"
            ],
        },
        "external_tools": {
            "volatility3": "Advanced memory forensics framework",
            "volatility2": "Legacy memory analysis (still widely used)",
            "rekall": "Memory analysis framework",
            "lime": "Linux memory acquisition tool",
            "dumpit": "Windows memory dumper",
        }
    },
    
    "vuln": {
        "modules": ["scanx"],
        "category": "Defensive Security",
        "description": "Vulnerability scanning and assessment",
        "related_tools": {
            "vulnerability_scanning": [
                "openvas", "nikto", "nessus", 
                "nuclei", "legion", "acunetix"
            ],
        },
        "external_tools": {
            "openvas": "Open-source vulnerability scanner",
            "nikto": "Web server scanner",
            "nessus": "Commercial vulnerability scanner",
            "nuclei": "Fast, template-based vulnerability scanner",
            "legion": "Automatic reconnaissance tool",
        }
    },
    
    "watch": {
        "modules": ["fimx"],
        "category": "Defensive Security",
        "description": "File integrity monitoring",
        "related_tools": {
            "file_integrity": [
                "aide", "tripwire", "inotifywait", 
                "ossec", "osquery", "samhain"
            ],
        },
        "external_tools": {
            "aide": "File integrity database creation and checking",
            "tripwire": "File integrity monitoring",
            "inotifywait": "Linux filesystem event monitoring",
            "ossec": "Host intrusion detection system",
            "osquery": "Operating system instrumentation",
        }
    },
    
    "comply": {
        "modules": ["cisx"],
        "category": "Defensive Security",
        "description": "CIS benchmark compliance checking",
        "related_tools": {
            "compliance_scanning": [
                "lynis", "openscap", "scap-workbench", 
                "inspec", "chef-compliance", "oval"
            ],
        },
        "external_tools": {
            "lynis": "Security auditing tool for Linux/Unix",
            "openscap": "Security compliance framework",
            "scap-workbench": "SCAP editing and scanning",
            "inspec": "Infrastructure compliance automation",
            "chef-compliance": "Compliance automation framework",
        }
    },
    
    # INFRASTRUCTURE & ANALYSIS TOOLS
    "lab": {
        "modules": ["vmx"],
        "category": "Infrastructure",
        "description": "Lab and virtual machine management",
        "related_tools": {
            "vm_management": [
                "vagrant", "proxmox", "virtualbox", 
                "packer", "terraform", "docker"
            ],
        },
        "external_tools": {
            "vagrant": "Virtual machine provisioning",
            "proxmox": "Open-source hypervisor",
            "virtualbox": "Virtual machine platform",
            "packer": "Machine image builder",
            "terraform": "Infrastructure as code",
        }
    },
    
    "report": {
        "modules": ["renderx"],
        "category": "Infrastructure",
        "description": "Report generation and management",
        "related_tools": {
            "reporting": [
                "dradis", "faraday", "piperka", 
                "pwndoc", "serpico", "defectdojo"
            ],
        },
        "external_tools": {
            "dradis": "Vulnerability collaboration framework",
            "faraday": "Unified vulnerability management",
            "piperka": "Security report generator",
            "pwndoc": "Penetration testing documentation",
            "serpico": "Security report generator",
        }
    },
    
    # ORIGINAL INTEGRATED TOOLS
    "frizz": {
        "modules": ["modx"],
        "category": "Original Tools",
        "description": "Protocol fuzzing",
        "related_tools": {
            "fuzzing": [
                "boofuzz", "aflplusplus", "spike", 
                "radamsa", "sulley", "libfuzzer"
            ],
        },
        "external_tools": {
            "boofuzz": "Protocol fuzzing framework",
            "aflplusplus": "Advanced fuzzing platform",
            "spike": "Fuzzing framework",
            "radamsa": "Mutation-based fuzzer",
            "sulley": "Intelligent fuzzing framework",
        }
    },
    
    "rift": {
        "modules": ["s3scan"],
        "category": "Original Tools",
        "description": "Cloud misconfiguration detection",
        "related_tools": {
            "cloud_scanning": [
                "prowler", "scoutsuite", "cloudsploit", 
                "pacu", "s3scanner", "trufflehog"
            ],
        },
        "external_tools": {
            "prowler": "AWS/Azure/GCP security audit",
            "scoutsuite": "Cloud security auditing tool",
            "cloudsploit": "Cloud security compliance checking",
            "pacu": "AWS exploitation framework",
            "trufflehog": "Secret scanning in git repos",
        }
    },
    
    "kerb": {
        "modules": ["tixr"],
        "category": "Original Tools",
        "description": "Active Directory and Kerberos attacks",
        "related_tools": {
            "kerberos_attacks": [
                "impacket", "bloodhound", "kerbrute", 
                "rubeus", "crackmapexec", "sharphound"
            ],
        },
        "external_tools": {
            "impacket": "Network protocols implementation suite",
            "bloodhound": "AD visualization and analysis",
            "kerbrute": "Kerberos user enumeration",
            "rubeus": "Kerberos abuse framework",
            "crackmapexec": "Post-exploitation framework",
        }
    },
    
    "spekt": {
        "modules": ["intel"],
        "category": "Original Tools",
        "description": "OSINT automation with Spiderfoot methodology",
        "related_tools": {
            "osint": [
                "maltego", "theharvester", "recon-ng", 
                "spiderfoot", "sherlock", "holehe"
            ],
        },
        "external_tools": {
            "maltego": "OSINT and graphical link analysis",
            "theharvester": "Email and subdomain enumeration",
            "recon-ng": "Web reconnaissance framework",
            "spiderfoot": "OSINT automation framework",
            "sherlock": "Username enumeration",
        }
    },
    
    "shade": {
        "modules": ["cloak"],
        "category": "Original Tools",
        "description": "Evasion and AV bypass",
        "related_tools": {
            "evasion": [
                "veil", "shellter", "invoke-obfuscation", 
                "scarecrow", "nimcrypt2", "hyperion"
            ],
        },
        "external_tools": {
            "veil": "AV bypass payload generator",
            "shellter": "Dynamic shellcode injection",
            "invoke-obfuscation": "PowerShell obfuscation",
            "scarecrow": "EDR evasion payload generator",
            "nimcrypt2": "AV evasion tool",
        }
    },
    
    "mobi": {
        "modules": ["droid"],
        "category": "Original Tools",
        "description": "Mobile application penetration testing",
        "related_tools": {
            "mobile_testing": [
                "apktool", "jadx", "mobsf", 
                "frida", "objection", "drozer"
            ],
        },
        "external_tools": {
            "apktool": "Android reverse engineering tool",
            "jadx": "Android decompiler",
            "mobsf": "Mobile security framework",
            "frida": "Dynamic instrumentation toolkit",
            "drozer": "Android security assessment",
        }
    },
    
    "firm": {
        "modules": ["flash"],
        "category": "Original Tools",
        "description": "Hardware and firmware security",
        "related_tools": {
            "firmware_analysis": [
                "binwalk", "flashrom", "openocd", 
                "firmwalker", "ghidra", "radare2"
            ],
        },
        "external_tools": {
            "binwalk": "Firmware analysis and extraction",
            "flashrom": "Firmware programmer",
            "openocd": "On-chip debugger",
            "firmwalker": "Firmware security scanning",
            "ghidra": "Reverse engineering framework",
        }
    },
    
    "wraith": {
        "modules": ["recon"],
        "category": "Original Tools",
        "description": "Post-exploitation and situational awareness",
        "related_tools": {
            "post_exploitation": [
                "linpeas", "winpeas", "bloodhound", 
                "enum4linux-ng", "seatbelt"
            ],
        },
        "external_tools": {
            "linpeas": "Linux privilege escalation scanner",
            "winpeas": "Windows privilege escalation scanner",
            "bloodhound": "AD mapping tool",
            "enum4linux-ng": "SMB/LDAP enumeration",
            "seatbelt": ".NET enumeration tool",
        }
    },
    
    "forge": {
        "modules": ["hunt"],
        "category": "Original Tools",
        "description": "Threat hunting and detection engineering",
        "related_tools": {
            "threat_hunting": [
                "sigma", "chainsaw", "hayabusa", 
                "velociraptor", "zeek", "yara"
            ],
        },
        "external_tools": {
            "sigma": "Generic signature format for SIEM",
            "chainsaw": "Rapid log analysis",
            "hayabusa": "Windows Event Log hunting",
            "velociraptor": "Endpoint monitoring/hunting",
            "zeek": "Network traffic analysis",
        }
    },
    
    "apix": {
        "modules": ["rest"],
        "category": "Original Tools",
        "description": "API security testing",
        "related_tools": {
            "api_security": [
                "ffuf", "arjun", "kiterunner", 
                "burpsuite", "restler", "nuclei"
            ],
        },
        "external_tools": {
            "ffuf": "Fast web fuzzer",
            "arjun": "API parameter discovery",
            "kiterunner": "API endpoint discovery",
            "burpsuite": "Web proxy and scanner",
            "restler": "API fuzzer",
        }
    },
}

# Cross-reference similar tools across different suites
TOOL_RELATIONSHIPS = {
    "subdomain_enumeration": ["recon.subx"],
    "sql_injection": ["webpwn.sqlix"],
    "credential_attacks": ["cred.sprayx"],
    "network_attacks": ["netpwn.vlanx"],
    "phishing": ["phish.campx"],
    "command_control": ["c2.server"],
    "lateral_movement": ["pivot.sockx"],
    "memory_forensics": ["blue.memx"],
    "vulnerability_scanning": ["vuln.scanx"],
    "file_integrity": ["watch.fimx"],
    "compliance": ["comply.cisx"],
    "osint": ["spekt.intel"],
    "evasion": ["shade.cloak"],
    "post_exploitation": ["wraith.recon"],
}

# Category definitions
CATEGORIES = {
    "Offensive Security": ["recon", "webpwn", "cred", "netpwn", "phish", "c2", "pivot"],
    "Defensive Security": ["blue", "vuln", "watch", "comply"],
    "Infrastructure": ["lab", "report"],
    "Original Tools": ["frizz", "rift", "kerb", "spekt", "shade", "mobi", "firm", "wraith", "forge", "apix"],
}

def get_suite_info(suite_name: str) -> dict:
    """Get information about a specific suite."""
    return TOOL_REGISTRY.get(suite_name, {})

def get_related_tools(tool_type: str) -> list:
    """Get related external tools for a specific tool type."""
    for suite, data in TOOL_REGISTRY.items():
        if tool_type in data.get("related_tools", {}):
            return data["related_tools"][tool_type]
    return []

def get_all_suites() -> list:
    """Get list of all available suites."""
    return sorted(list(TOOL_REGISTRY.keys()))

def get_suite_modules(suite_name: str) -> list:
    """Get modules available in a suite."""
    suite_data = TOOL_REGISTRY.get(suite_name, {})
    return suite_data.get("modules", [])

def get_category_suites(category: str) -> list:
    """Get all suites in a category."""
    return CATEGORIES.get(category, [])

def find_suite_by_module(module_name: str) -> str:
    """Find which suite contains a specific module."""
    for suite, data in TOOL_REGISTRY.items():
        if module_name in data.get("modules", []):
            return suite
    return None

def print_tool_relationships(suite_name: str):
    """Print related external tools for a suite."""
    suite_data = TOOL_REGISTRY.get(suite_name)
    if not suite_data:
        return None
    
    output = f"\n[bold cyan]Related External Tools for {suite_name.upper()}:[/bold cyan]\n"
    
    for tool_type, tools in suite_data.get("related_tools", {}).items():
        output += f"  [bold yellow]{tool_type.replace('_', ' ').title()}:[/bold yellow]\n"
        for tool in tools:
            output += f"    • {tool}\n"
    
    return output

def get_tool_description(suite_name: str, tool_name: str) -> str:
    """Get description of a specific external tool."""
    suite_data = TOOL_REGISTRY.get(suite_name, {})
    external_tools = suite_data.get("external_tools", {})
    return external_tools.get(tool_name, "No description available")

if __name__ == "__main__":
    # Test the registry
    print("Available Suites:", get_all_suites())
    print("\nSpekt Modules:", get_suite_modules("spekt"))
    print("\nOffensive Security Suites:", get_category_suites("Offensive Security"))
