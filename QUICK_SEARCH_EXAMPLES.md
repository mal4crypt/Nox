# Quick Search Examples

## 5-Second Quick Start

```bash
$ python3 nox
nox > find sql           # Find SQL tools → webpwn
nox > run kerb           # Quick-launch → kerb/tixr
nox > info spekt         # Get tool info
nox > find -c Offensive  # Browse attack tools
nox > help               # Full help
```

---

## Common Searches (Copy & Paste)

### Finding by Name
```
find sql          → webpwn/sqlix (Web exploitation)
find kerb         → kerb/tixr (Active Directory)
find recon        → recon/subx (Reconnaissance)
find memory       → blue/memx (Incident Response)
find cloud        → rift/s3scan (Cloud security)
find c2           → c2/server (Command & Control)
```

### Finding by Capability
```
find -k password  → cred/sprayx (Credential attacks)
find -k forensics → blue/memx (Memory forensics)
find -k scanning  → vuln/scanx (Vulnerability scanning)
find -k web       → webpwn/sqlix (Web exploitation)
find -k phishing  → phish/campx (Phishing campaigns)
```

### Finding by Category
```
find -c Offensive       → All 10 attack tools
find -c Defensive       → All 5 defense tools
find -c Infrastructure  → All lab/reporting tools
```

### Quick-Launch Examples
```
run sql           → Auto-launches webpwn/sqlix
run kerb          → Auto-launches kerb/tixr
run spekt         → Auto-launches spekt/intel
run memory        → Auto-launches blue/memx
run c2            → Auto-launches c2/server
```

### Getting Details
```
info spekt        → Show SPEKT details
info webpwn       → Show WEBPWN details
info kerb         → Show KERB details
info blue         → Show BLUE details
```

### Find Related Tools
```
relate spekt      → Find OSINT-related tools
relate kerb       → Find AD-related tools
relate webpwn     → Find web-related tools
```

---

## Real Scenarios

### Scenario 1: "I want to test SQL injection"
```
nox > find sql
# → Shows webpwn/sqlix
nox > run sql
# → Launches webpwn
webpwn > sqlix --help
```

### Scenario 2: "I need to do AD enumeration"
```
nox > find kerb
# → Shows kerb/tixr
nox > run kerb
# → Auto-launches kerb/tixr
```

### Scenario 3: "Show me all available attack tools"
```
nox > find -c Offensive
# → Shows all 10 offensive security tools
```

### Scenario 4: "I forgot the tool name for password spraying"
```
nox > find -k password
# → Shows cred/sprayx (Credential attacks)
nox > run password
# → Launches credential tools
```

### Scenario 5: "What tools can I use after OSINT?"
```
nox > relate spekt
# → Shows tools that work with spekt/intel
```

---

## Search Tips

### Tip 1: Don't Remember Module Names?
Instead of: `nox webpwn sqlix --help`
Just type: `nox > run sql` then `--help`

### Tip 2: Discover Tools by Category
```
nox > find -c Offensive     # Browse all attack tools
nox > find -c Defensive     # Browse all defense tools
```

### Tip 3: Find Tools by Capability
When you don't remember the exact tool name:
```
nox > find -k password      # Find password tools
nox > find -k forensics     # Find forensics tools
nox > find -k cloud         # Find cloud tools
```

### Tip 4: Quick-Launch Single-Module Tools
```
nox > run kerb              # Auto-launches kerb/tixr
nox > run spekt             # Auto-launches spekt/intel
nox > run c2                # Auto-launches c2/server
```

### Tip 5: See External Tool Integrations
```
nox > find -e sqlmap        # See Nox tools using sqlmap
nox > find -e amass         # See Nox tools using Amass
```

---

## Comparison: Before vs After

### Before (Had to Remember Everything)
```bash
# If you forgot which suite has SQL injection...
$ nox help
$ cat TOOL_RELATIONSHIPS.md
$ python3 nox
nox > list
# Found it! It's webpwn
nox > webpwn sqlix --domain target.com
```

### After (Just Search)
```bash
$ python3 nox
nox > find sql
# → webpwn (Match: 95%)
nox > run sql
# → Launches webpwn
webpwn > sqlix --domain target.com
```

**Time saved:** 80% faster! 🚀

---

## All Search Commands

```
find <query>          - Fuzzy search by name
find -k <query>       - Search by keyword/capability
find -c <category>    - Browse by category
find -e <tool>        - Find external tool integrations
run <query>           - Quick-launch tool
info <suite>          - Get tool details
relate <suite>        - Find related tools
list                  - List all tools (old way)
help                  - Show help
help find             - Show search help
```

---

## Keyboard Shortcuts in Shell

```
↑/↓               - Command history
Ctrl+C            - Exit tool
Ctrl+L            - Clear screen
Tab               - (Might show completions)
```

---

## Getting Help

```
nox > help              # General help
nox > help find         # Help for find command
nox > info <suite>      # Details about specific tool
cat SEARCH_GUIDE.md     # Full search documentation
cat SEARCH_FEATURES.md  # Feature overview (this file)
python3 demo_search.py  # Interactive demo
```

---

## Pro Tips

### Tip 1: Build Attack Chains
```
nox > relate spekt       # What comes after OSINT?
nox > run kerb           # Try Kerberos enumeration
nox > relate kerb        # What comes after Kerb?
nox > run c2             # Set up C2
```

### Tip 2: Explore by Category
```
nox > find -c Offensive  # See all attack tools
nox > find -c Defensive  # See all defense tools
```

### Tip 3: Use Partial Names
```
find sql      # Finds webpwn (has sqlix module)
find pass     # Finds cred (password spraying)
find cloud    # Finds rift (cloud scanning)
```

### Tip 4: Tab Completion
While typing, press Tab to see suggestions (if implemented):
```
nox > find s[TAB]     # Shows: sql, spekt, shade...
nox > run k[TAB]      # Shows: kerb...
nox > info s[TAB]     # Shows: spekt, shade...
```

---

## FAQ

**Q: Do I still use `nox suite module` command?**
A: Yes! Both ways work. Search is just faster and easier.

**Q: What if there are multiple matches?**
A: Single-module tools auto-launch. Multi-module tools show a menu.

**Q: Can I search by external tool names?**
A: Yes! `find -e sqlmap` shows Nox tools using sqlmap.

**Q: How fast is the search?**
A: Sub-millisecond. All 23 tools indexed instantly.

**Q: Do I need to install anything?**
A: No! It uses Python built-in modules only.

**Q: Can I use search with command-line Nox?**
A: Currently search is shell-only. CLI commands still work as-is.

---

## Examples by Domain

### Offensive Security
```
find -c Offensive          # Show all 10 attack tools
find kerb                  # Find AD tools
find sql                   # Find web tools
find -k password           # Find password tools
run c2                     # Quick-launch C2
```

### Defensive Security
```
find -c Defensive          # Show all 5 defense tools
find blue                  # Find incident response
find -k forensics          # Find forensics tools
run scan                   # Quick-launch vulnerability scanning
```

### Infrastructure
```
find -c Infrastructure     # Show infrastructure tools
find lab                   # Find lab setup
find report                # Find reporting tools
```

---

## Need More Help?

```bash
# Start the shell
python3 nox

# Try these commands
nox > help                # General help
nox > help find          # Search help
nox > find sql           # Find SQL tools
nox > info spekt         # Get tool details
nox > find -c Offensive  # Browse tools

# Read documentation
cat SEARCH_GUIDE.md      # Complete guide
cat SEARCH_FEATURES.md   # Feature overview

# See interactive demo
python3 demo_search.py
```

---

## Summary

✅ **Easy to use:** Just type `find sql` instead of remembering `webpwn sqlix`
✅ **Multiple search methods:** By name, keyword, category, or integration
✅ **Quick-launch:** `run kerb` auto-executes single-module tools
✅ **Discovery:** `find -c Offensive` shows all available tools
✅ **Integration:** Works seamlessly with existing Nox commands

**Happy hunting! 🎯**

