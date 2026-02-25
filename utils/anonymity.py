#!/usr/bin/env python3
"""
NOX Anonymity & Anti-Forensics Module
Purpose: Keep users digitally invisible during operations
Features: Proxy routing, identity masking, log obfuscation, digital fingerprint removal
"""

import random
import string
import hashlib
import socket
import subprocess
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional

class AnonymityManager:
    """Manages user anonymity and anti-forensics"""
    
    # Common user agents (rotating)
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15",
        "curl/7.64.1",
        "Wget/1.20.3",
        "python-requests/2.28.0"
    ]
    
    # Proxy lists (free public proxies for anonymity)
    PROXY_POOLS = [
        "http://proxy1.anonymousnet.com:8080",
        "http://proxy2.vpnservice.net:3128",
        "socks5://anonymous.proxy.org:1080",
        "http://tor-exit.proxy.com:8888"
    ]
    
    # VPN providers for exit node rotation
    VPN_PROVIDERS = [
        {"name": "ProtonVPN", "region": "Switzerland"},
        {"name": "NordVPN", "region": "Iceland"},
        {"name": "ExpressVPN", "region": "Panama"},
        {"name": "Mullvad", "region": "Sweden"}
    ]
    
    def __init__(self, enable_vpn=False, enable_proxy=False, spoof_timezone=False):
        """Initialize anonymity manager"""
        self.enable_vpn = enable_vpn
        self.enable_proxy = enable_proxy
        self.spoof_timezone = spoof_timezone
        self.session_id = self._generate_session_id()
        self.user_agent = random.choice(self.USER_AGENTS)
        self.proxy = random.choice(self.PROXY_POOLS) if enable_proxy else None
        self.vpn_provider = random.choice(self.VPN_PROVIDERS) if enable_vpn else None
        
    def _generate_session_id(self) -> str:
        """Generate anonymous session ID"""
        return hashlib.sha256(
            f"{datetime.now().isoformat()}{random.random()}".encode()
        ).hexdigest()[:16]
    
    def get_spoofed_headers(self) -> Dict:
        """Get HTTP headers that mask identity"""
        return {
            "User-Agent": self.user_agent,
            "X-Forwarded-For": self._generate_random_ip(),
            "X-Real-IP": self._generate_random_ip(),
            "X-Client-IP": self._generate_random_ip(),
            "CF-Connecting-IP": self._generate_random_ip(),
            "Accept-Language": random.choice(["en-US,en;q=0.9", "de-DE,de;q=0.9", "fr-FR,fr;q=0.9"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": self._generate_random_referrer(),
            "DNT": "1",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }
    
    def _generate_random_ip(self) -> str:
        """Generate random IP address (non-routable for spoofing)"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    def _generate_random_referrer(self) -> str:
        """Generate random referrer"""
        sites = [
            "https://www.google.com/search?q=",
            "https://www.bing.com/search?q=",
            "https://www.duckduckgo.com/?q=",
            "https://www.linkedin.com/",
            "https://www.twitter.com/",
            "https://www.github.com/"
        ]
        return random.choice(sites)
    
    def get_anonymized_socket_options(self) -> Dict:
        """Get socket options for anonymization"""
        return {
            "disable_dns_leaks": True,
            "use_socks5": self.enable_proxy,
            "randomize_port": True,
            "spoof_mac": True,
            "clear_cache": True
        }
    
    def get_logging_config(self) -> Dict:
        """Get config to prevent forensic evidence"""
        return {
            "log_to_syslog": False,
            "clear_bash_history": True,
            "disable_command_history": True,
            "overwrite_temp_files": True,
            "randomize_timestamps": True,
            "remove_metadata": True,
            "shred_sensitive_data": True
        }
    
    def cleanup_tracks(self) -> bool:
        """Remove digital footprints"""
        try:
            # Clear bash history
            subprocess.run(
                "history -c && history -w",
                shell=True,
                capture_output=True,
                timeout=5
            )
            
            # Overwrite temp files
            temp_dirs = ["/tmp", os.path.expanduser("~/.cache"), os.path.expanduser("~/.local/share/recently-used")]
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    subprocess.run(
                        f"find {temp_dir} -type f -atime +0 -delete 2>/dev/null",
                        shell=True,
                        timeout=10
                    )
            
            return True
        except Exception as e:
            return False
    
    def generate_decoy_traffic(self, duration_seconds: int = 60) -> Dict:
        """Generate decoy traffic to mask real activity"""
        decoy_activities = {
            "dns_queries": [
                "github.com", "stackoverflow.com", "python.org",
                "google.com", "wikipedia.org", "amazon.com"
            ],
            "http_requests": [
                "https://www.github.com/trending",
                "https://www.python.org/downloads",
                "https://stackoverflow.com/questions"
            ],
            "fake_ports": [80, 443, 8080, 3306, 5432, 6379],
            "fake_processes": ["chrome", "firefox", "vscode", "python"]
        }
        
        return {
            "decoy_config": decoy_activities,
            "duration": duration_seconds,
            "traffic_pattern": "random",
            "description": "Background noise to mask real operations"
        }
    
    def get_vpn_config(self) -> Optional[Dict]:
        """Get VPN configuration for anonymized exit"""
        if not self.vpn_provider:
            return None
        
        return {
            "provider": self.vpn_provider["name"],
            "region": self.vpn_provider["region"],
            "protocol": random.choice(["OpenVPN", "IKEv2", "WireGuard"]),
            "kill_switch": True,
            "dns_leak_protection": True,
            "ipv6_leak_protection": True,
            "rotate_every": 300  # seconds
        }
    
    def obfuscate_payload(self, payload: str) -> str:
        """Obfuscate command payloads"""
        methods = [
            self._base64_encode,
            self._hex_encode,
            self._rot13_encode,
            self._random_variable_encode
        ]
        
        obfuscation_method = random.choice(methods)
        return obfuscation_method(payload)
    
    def _base64_encode(self, text: str) -> str:
        """Base64 encoding"""
        import base64
        return f"echo {base64.b64encode(text.encode()).decode()} | base64 -d | bash"
    
    def _hex_encode(self, text: str) -> str:
        """Hex encoding"""
        hex_payload = ''.join(f'\\x{ord(c):02x}' for c in text)
        return f"echo -e '{hex_payload}' | bash"
    
    def _rot13_encode(self, text: str) -> str:
        """ROT13 encoding"""
        import codecs
        return codecs.encode(text, 'rot_13')
    
    def _random_variable_encode(self, text: str) -> str:
        """Random variable encoding"""
        var_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        return f"{var_name}='{text}'; eval $({var_name})"
    
    def get_anonymity_status(self) -> Dict:
        """Get current anonymity configuration status"""
        return {
            "session_id": self.session_id,
            "vpn_enabled": self.enable_vpn,
            "vpn_provider": self.vpn_provider,
            "proxy_enabled": self.enable_proxy,
            "proxy_url": self.proxy,
            "user_agent": self.user_agent,
            "timezone_spoofing": self.spoof_timezone,
            "features": {
                "header_spoofing": True,
                "dns_leak_protection": True,
                "track_cleanup": True,
                "decoy_traffic": True,
                "payload_obfuscation": True,
                "metadata_removal": True
            }
        }
    
    def install_vpn(self, provider: str = "Mullvad") -> bool:
        """Attempt to install VPN"""
        try:
            # Mullvad installation commands
            commands = [
                "curl https://repository.mullvad.net/install.sh | sudo bash",
                "sudo apt install mullvad -y",
                "sudo systemctl start mullvad-daemon"
            ]
            
            for cmd in commands:
                try:
                    subprocess.run(cmd, shell=True, timeout=30, capture_output=True)
                    return True
                except:
                    continue
            
            return False
        except Exception as e:
            return False
    
    def rotate_identity(self):
        """Rotate user identity (IP, headers, user agent)"""
        self.user_agent = random.choice(self.USER_AGENTS)
        self.proxy = random.choice(self.PROXY_POOLS) if self.enable_proxy else None
        self.vpn_provider = random.choice(self.VPN_PROVIDERS) if self.enable_vpn else None
        self.session_id = self._generate_session_id()
        
        return self.get_anonymity_status()


class ForensicsEvasion:
    """Evasion techniques to prevent forensic analysis"""
    
    @staticmethod
    def remove_file_metadata(filepath: str) -> bool:
        """Remove metadata from files"""
        try:
            subprocess.run(f"exiftool -all= '{filepath}'", shell=True, capture_output=True, timeout=5)
            subprocess.run(f"touch -t 202001010000 '{filepath}'", shell=True, capture_output=True)
            return True
        except:
            return False
    
    @staticmethod
    def secure_delete(filepath: str, passes: int = 7) -> bool:
        """Securely delete file (DOD 5220.22-M standard)"""
        try:
            subprocess.run(f"shred -vfz -n {passes} '{filepath}'", shell=True, capture_output=True, timeout=10)
            return True
        except:
            return False
    
    @staticmethod
    def disable_audit_logging() -> bool:
        """Disable system audit logging"""
        try:
            subprocess.run("sudo auditctl -a never,exit -S all", shell=True, capture_output=True)
            return True
        except:
            return False
    
    @staticmethod
    def clear_system_logs() -> bool:
        """Clear system logs"""
        try:
            log_files = [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/apache2/access.log",
                "/var/log/apache2/error.log",
                os.path.expanduser("~/.bash_history"),
                os.path.expanduser("~/.zsh_history"),
                os.path.expanduser("~/.local/share/recently-used.xbel")
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    subprocess.run(f"echo '' | sudo tee {log_file}", shell=True, capture_output=True)
            
            return True
        except:
            return False
    
    @staticmethod
    def spoof_system_info() -> Dict:
        """Get system info spoofing data"""
        return {
            "fake_hostname": f"user-{random.randint(1000, 9999)}",
            "fake_username": f"guest_{random.randint(1000, 9999)}",
            "fake_timezone": random.choice(["UTC", "EST", "PST", "GMT", "JST"]),
            "fake_locale": random.choice(["en_US", "de_DE", "fr_FR", "ja_JP"]),
            "fake_uptime": f"{random.randint(1, 30)} days"
        }
