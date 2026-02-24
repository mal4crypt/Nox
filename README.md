# Nox - Unified Offensive Security Research Suite

Nox is a comprehensive modular framework featuring 23 specialized security tools across offensive, defensive, and infrastructure testing domains.

## Project Structure

**Offensive Security (7 tools)**
- `recon/subx`: Subdomain enumeration
- `webpwn/sqlix`: SQL injection testing
- `cred/sprayx`: Password spraying
- `netpwn/vlanx`: Network infrastructure attacks
- `phish/campx`: Phishing campaign management
- `c2/server`: Command & Control framework
- `pivot/sockx`: SOCKS proxy & lateral movement

**Defensive Security (4 tools)**
- `blue/memx`: Memory analysis & forensics
- `vuln/scanx`: Vulnerability scanning
- `watch/fimx`: File integrity monitoring
- `comply/cisx`: CIS benchmark compliance

**Infrastructure & Analysis (2 tools)**
- `lab/vmx`: Attack lab environment management
- `report/renderx`: Report generation

**Original Integrated Tools (10 tools)**
- `frizz/modx`: Protocol Fuzzers
- `rift/s3scan`: Cloud Misconfiguration Scanner
- `kerb/tixr`: Active Directory & Kerberos Attacks
- `spekt/intel`: OSINT Automation
- `shade/cloak`: Evasion & AV Bypass
- `mobi/droid`: Mobile Pentesting
- `firm/flash`: Hardware & Embedded Security
- `wraith/recon`: Post-Exploitation & Situational Awareness
- `forge/hunt`: Threat Hunting & Detection Engineering
- `apix/rest`: API Security Testing

## Usage
```bash
nox <suite> <module> [arguments]
```

## Legal
Refer to `DISCLAIMER.md` for ethical use and legal requirements. Authorized use only.

---

## How It Works: Framework Architecture

The Nox framework is designed around a **Modular Dispatch Architecture**. This allows it to act as a unified interface for disparate security tools, standardizing how they are launched, how arguments are parsed, and how output is handled.

### 1. The Master Launcher (`nox.py`)
At the core of the framework is `nox.py`. It is responsible for intercepting command-line arguments and routing execution to the correct submodule.

**Execution Flow:**
1. **Argument Interception:** When you run `nox <suite> <module> [args]`, `nox` captures the first two positional arguments (e.g., `spekt` and `intel`).
2. **Dynamic Import:** It uses Python's `importlib` to dynamically import the target script on the fly (e.g., `importlib.import_module('spekt.intel')`). This ensures that dependencies for uncalled modules aren't loaded into memory unnecessarily.
3. **Context Hand-off:** `nox` rewrites `sys.argv` so that when control is passed to the submodule, the submodule's `argparse` believes it was called directly via `nox <suite> <module>`.
4. **Execution:** It calls the `main()` function of the dynamically loaded module.

### 2. Standardized Submodules
Every tool inside the subdirectories (e.g., `kerb/tixr.py`, `frizz/modx.py`) adheres to a strict contract to integrate with the framework:
- **`main()` Entrypoint:** Every script must have a `def main():` function that serves as the execution trigger.
- **Consistent Argument Parsing:** Modules use `argparse` to handle their specific flags (like `--domain`, `--wordlist`).
- **Legal Check:** Every module includes a mandatory `--confirm-legal` flag or an interactive prompt forcing the user to confirm authorization before executing offensive actions.
- **Formatting Utilities:** Modules leverage shared utilities (`utils/logger.py` and `utils/formatter.py`) to standardize output formats (JSON, CSV, TXT) and maintain operational security logs in the `./logs/` directory.

### 3. Shared Utilities (`utils/`)
To prevent code duplication across 10 different security tools, Nox uses a central utilities folder:
- `banner.py`: Handles the drawing of the specialized FIGlet ASCII art and UI borders for each tool.
- `logger.py`: Provides automated, standardized audit logging so that all tool executions, parameters, and timestamps are recorded for reporting or post-engagement analysis.
- `formatter.py`: Converts raw Python dictionaries (findings) into structured JSON, CSV, or Text files based on the `--output` flag provided to the submodule.
