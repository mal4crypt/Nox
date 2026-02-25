# Nox Tool Search & Quick-Launch Guide

## Overview

The Nox Framework now includes an intelligent **tool search and quick-launch system** that lets you find and execute tools by typing just a few characters—no need to remember the full suite/module structure.

## Quick Start Examples

```
# Find tools by name (fuzzy search)
nox > find sql              # Find SQL-related tools
nox > find kerb             # Find Kerberos tools
nox > find recon            # Find reconnaissance tools

# Quick-launch a tool
nox > run sql               # Launches webpwn/sqlix
nox > run kerb              # Launches kerb/tixr
nox > run cloud             # Search for cloud tools and show options

# Get detailed info about a tool
nox > info spekt            # Show detailed info about spekt
nox > info webpwn           # Show detailed info about webpwn

# Find related tools
nox > relate spekt          # Find tools that work with spekt
nox > relate kerb           # Find Kerberos-related tools
```

---

## Commands Reference

### `find` - Search for Tools

#### Basic Fuzzy Search
```
find <query>
```
Fuzzy search for tools by suite name or module name. Uses intelligent matching to find close matches.

**Examples:**
```
nox > find sql              # Find SQL-related tools
nox > find spekt            # Find SPEKT suite
nox > find memory           # Find tools with "memory" in name/description
nox > find vlan             # Find VLAN-related tools
```

**How it works:**
- Exact match → Highest score
- Prefix match (tool name starts with query) → High score
- Substring match → Medium score
- Fuzzy match → Lower score but still finds similar names

---

#### Keyword Search
```
find -k <query>
```
Search for tools by functionality, capability, or category. Great for discovering what tools can do.

**Examples:**
```
nox > find -k password      # Find password/credential tools
nox > find -k "web exploit" # Find web exploitation tools
nox > find -k memory        # Find memory analysis tools
nox > find -k compliance    # Find compliance/audit tools
```

**What it searches:**
- Tool descriptions
- Category keywords
- Module names
- Functionality tags

---

#### Category Search
```
find -c <category>
```
Find all tools in a specific security domain.

**Examples:**
```
nox > find -c "Offensive"           # Find all offensive security tools
nox > find -c "Defensive"           # Find all defensive security tools
nox > find -c "Infrastructure"      # Find infrastructure tools
```

**Available Categories:**
- `Offensive Security` - Penetration testing, exploitation, attack tools
- `Defensive Security` - Detection, response, monitoring tools
- `Infrastructure` - Lab setup, reporting, framework tools

---

#### External Tool Search
```
find -e <external_tool>
```
Find Nox tools that integrate with specific external tools or frameworks.

**Examples:**
```
nox > find -e sqlmap        # Find tools using sqlmap
nox > find -e metasploit    # Find tools using Metasploit
nox > find -e mimikatz      # Find tools using Mimikatz
nox > find -e amass         # Find tools using Amass
```

---

### `run` - Quick-Launch a Tool

```
run <query>
```
Quick-launch a tool by partial name. If the match is unambiguous, it auto-executes. If there are multiple options, you can choose.

**Examples:**
```
nox > run sql               # Auto-launches webpwn/sqlix
nox > run kerb              # Auto-launches kerb/tixr
nox > run spekt             # Auto-launches spekt/intel
nox > run azure             # Shows matching tools (rift has cloud modules)
```

**Behavior:**
- **Single match** → Auto-executes immediately
- **Multiple matches** → Shows list of options to choose from
- **No match** → Suggests similar tools

---

### `info` - Tool Details

```
info <suite>
```
Display comprehensive information about a tool, including description, modules, and integrated external tools.

**Examples:**
```
nox > info spekt
nox > info kerb
nox > info webpwn
nox > info blue
```

**Information shown:**
- Tool description
- Category (Offensive/Defensive/Infrastructure)
- Available modules
- Integrated external tools
- Related tools

---

### `relate` - Find Related Tools

```
relate <suite>
```
Show tools that are related to the given tool. Useful for building attack chains or understanding tool ecosystems.

**Examples:**
```
nox > relate spekt           # Tools that work with spekt (OSINT)
nox > relate webpwn          # Related web exploitation tools
nox > relate kerb            # Related AD/Kerberos tools
nox > relate blue            # Related incident response tools
```

---

## Search Examples by Use Case

### Finding Reconnaissance Tools
```
nox > find recon            # Direct search
nox > find -k reconnaissance # Keyword search
nox > find -c "Offensive"   # Category search (includes recon)
```

### Finding Credential Attack Tools
```
nox > find cred             # Search by suite name
nox > find -k password      # Keyword search
nox > run password          # Quick launch
```

### Finding Web Exploitation Tools
```
nox > find webpwn           # Direct search
nox > find -k "web exploit" # Keyword search
nox > find -e sqlmap        # Find tools using sqlmap
```

### Finding Cloud Security Tools
```
nox > find cloud            # Search by name
nox > find -k "cloud"       # Keyword search
nox > find -c "Offensive"   # Look in offensive category
```

### Finding Incident Response Tools
```
nox > find blue             # Direct search
nox > find -k "forensics"   # Keyword search
nox > find -c "Defensive"   # Find in defensive category
```

---

## Integration with Traditional Commands

All search/launch functionality works seamlessly with traditional Nox commands:

```
# Traditional way (still works)
nox spekt intel --domain example.com

# Quick-launch way
nox > run spekt
spekt > intel --domain example.com

# Combined
nox > run intel             # Might find multiple "intel" suites
                            # Shows options to choose from
```

---

## Advanced Tips

### Building Attack Chains
```
# Use 'relate' to find the next tool in your workflow
nox > relate spekt          # Find tools that work with OSINT
nox > run kerb              # Move to Kerberos enumeration
nox > relate kerb           # Find lateral movement tools
nox > run pivot             # Jump to lateral movement
```

### Discovering New Tools
```
# Browse by category
nox > find -c "Offensive"   # See all offensive tools
nox > find -c "Defensive"   # See all defensive tools

# Then get details
nox > info webpwn           # Learn about web exploitation
nox > info comply           # Learn about compliance tools
```

### Finding Tool Combinations
```
# Tools that integrate with popular frameworks
nox > find -e metasploit    # Tools for Metasploit integration
nox > find -e nuclei        # Tools for Nuclei templates
nox > find -e crackmapexec  # Tools for CrackMapExec integration
```

---

## Search Behavior & Scoring

### Fuzzy Search Scoring
- **1.0** - Exact match (you typed the exact tool name)
- **0.95** - Prefix match (tool name starts with your query)
- **0.85** - Substring match (your query appears in tool name)
- **0.6-0.8** - Fuzzy match (similar but not identical)

### Keyword Search Scoring
- **1.0** - Keyword found in description or module name
- **0.8** - Found in category
- **0.6+** - Multiple keyword matches

---

## Troubleshooting Search

### "No results found"
- Try a different search term
- Use `find -c` to browse by category
- Use `find -k` for keyword search
- Check tool availability with `list`

### Getting too many results
- Be more specific with your query
- Use `-k` for keyword search instead of fuzzy
- Use `info <tool>` to examine specific tools

### Can't remember the tool name
- Use `find -k` with the functionality you need
- Use `find -c` to browse by category
- Use `relate <tool>` to find similar tools

---

## Technical Details

### Search Index
The search system builds an index of:
- Suite names and modules
- Tool descriptions
- Keywords extracted from descriptions
- Categories
- External tool integrations

### Matching Algorithm
1. **Fuzzy matching** - String similarity using SequenceMatcher
2. **Prefix matching** - Tools starting with your query
3. **Substring matching** - Your query appears in tool name
4. **Keyword matching** - Keywords from descriptions
5. **Category matching** - Security domain categorization

### Performance
- Instant search (sub-millisecond)
- All 23 tools searchable
- 115+ external tool references indexed

---

## Quick Reference Table

| Command | Purpose | Example |
|---------|---------|---------|
| `find <q>` | Fuzzy search by name | `find sql` |
| `find -k <q>` | Keyword search | `find -k password` |
| `find -c <q>` | Category search | `find -c Offensive` |
| `find -e <q>` | External tool search | `find -e sqlmap` |
| `run <q>` | Quick-launch | `run kerb` |
| `info <s>` | Tool details | `info spekt` |
| `relate <s>` | Related tools | `relate kerb` |
| `list` | All tools | `list` |
| `help` | General help | `help` |

---

## Examples by Tool

### SPEKT (OSINT)
```
nox > find spekt            # Find by name
nox > find -k osint         # Find by keyword
nox > run intel             # Quick-launch intel module
nox > info spekt            # Get details
nox > relate spekt          # Find related tools
```

### KERB (Active Directory)
```
nox > find kerb             # Find by name
nox > find -k kerberos      # Find by keyword
nox > run tixr              # Quick-launch tixr module
nox > info kerb             # Get details
nox > relate kerb           # Find AD-related tools
```

### WEBPWN (Web Exploitation)
```
nox > find webpwn           # Find by name
nox > find -k "web exploit" # Find by keyword
nox > run sql               # Quick-launch sqlix module
nox > info webpwn           # Get details
nox > relate webpwn         # Find related tools
```

### BLUE (Incident Response)
```
nox > find blue             # Find by name
nox > find -k memory        # Find by keyword
nox > run memx              # Quick-launch memx module
nox > info blue             # Get details
nox > relate blue           # Find related tools
```

---

## Feedback & Usage

The search system is designed to make tool discovery intuitive:
- **Type naturally** - "find password" not "find cred"
- **Be flexible** - Multiple ways to search work
- **Combine methods** - Use `relate` after `run` for chains
- **Explore** - Try `find -c` to browse categories

For more help:
```
nox > help                  # General help
nox > help find             # Help for find command
nox > info <tool>           # Get details about a tool
```

