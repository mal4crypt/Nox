#!/usr/bin/env python3
"""
Nox Tool Search & Quick Launch System
Provides fuzzy search, tool discovery, and intelligent command generation
"""

from difflib import SequenceMatcher
from typing import List, Tuple, Dict, Optional
from utils.tool_registry import TOOL_REGISTRY, TOOL_RELATIONSHIPS, CATEGORIES
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class ToolSearcher:
    """Search and discover Nox tools by name, keyword, or functionality."""
    
    def __init__(self):
        """Initialize the tool searcher with registry data."""
        self.registry = TOOL_REGISTRY
        self.relationships = TOOL_RELATIONSHIPS
        self.categories = CATEGORIES
        self._build_search_index()
    
    def _build_search_index(self) -> None:
        """Build a searchable index of all tools and their attributes."""
        self.search_index = {}
        
        for suite, data in self.registry.items():
            modules = data.get("modules", [])
            description = data.get("description", "")
            category = data.get("category", "")
            external_tools = data.get("external_tools", {})
            
            # Extract keywords from description and suite name
            keywords = self._extract_keywords(description, category, suite)
            
            # Index by suite name
            self.search_index[suite] = {
                "suite": suite,
                "modules": modules,
                "description": description,
                "category": category,
                "type": "suite",
                "keywords": keywords,
                "external_tools": list(external_tools.keys()),
            }
    
    def _extract_keywords(self, *texts: str) -> set:
        """Extract searchable keywords from text."""
        keywords = set()
        for text in texts:
            if text:
                # Split into words, lowercase, remove common words
                words = text.lower().split()
                for word in words:
                    if len(word) > 2 and word not in ["and", "the", "for", "with"]:
                        keywords.add(word.strip(".,!?;:"))
        return keywords
    
    def fuzzy_match(self, query: str, candidates: List[str], threshold: float = 0.6) -> List[Tuple[str, float]]:
        """
        Fuzzy match query against candidates.
        Returns list of (candidate, score) tuples sorted by score.
        """
        results = []
        query_lower = query.lower()
        
        for candidate in candidates:
            candidate_lower = candidate.lower()
            
            # Exact match gets highest score
            if query_lower == candidate_lower:
                results.append((candidate, 1.0))
                continue
            
            # Prefix match gets high score
            if candidate_lower.startswith(query_lower):
                results.append((candidate, 0.95))
                continue
            
            # Substring match
            if query_lower in candidate_lower:
                results.append((candidate, 0.85))
                continue
            
            # Fuzzy match using SequenceMatcher
            ratio = SequenceMatcher(None, query_lower, candidate_lower).ratio()
            if ratio >= threshold:
                results.append((candidate, ratio))
        
        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results
    
    def search_by_name(self, query: str, limit: int = 10) -> List[Dict]:
        """Search for tools by suite or module name."""
        candidates = list(self.search_index.keys())
        matches = self.fuzzy_match(query, candidates, threshold=0.6)
        
        results = []
        seen_suites = set()
        
        # First add matches for suite names
        for suite_name, score in matches[:limit]:
            if suite_name not in seen_suites:
                data = self.search_index[suite_name]
                results.append({
                    "suite": suite_name,
                    "modules": data["modules"],
                    "description": data["description"],
                    "category": data["category"],
                    "score": score,
                    "match_type": "suite_name"
                })
                seen_suites.add(suite_name)
        
        # Also search for module names
        for suite_name, data in self.search_index.items():
            if suite_name in seen_suites:
                continue
            
            modules = data["modules"]
            for module in modules:
                module_matches = self.fuzzy_match(query, [module], threshold=0.6)
                if module_matches:
                    score = module_matches[0][1]
                    results.append({
                        "suite": suite_name,
                        "modules": modules,
                        "description": data["description"],
                        "category": data["category"],
                        "score": score,
                        "match_type": "module_name"
                    })
                    seen_suites.add(suite_name)
                    break
        
        # Sort by score descending
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:limit]
    
    def search_by_keyword(self, query: str, limit: int = 10) -> List[Dict]:
        """Search for tools by functionality or category."""
        query_keywords = self._extract_keywords(query)
        scored_results = []
        
        for suite, data in self.search_index.items():
            tool_keywords = data["keywords"]
            # Calculate keyword overlap
            overlap = query_keywords & tool_keywords
            if overlap:
                score = len(overlap) / max(len(query_keywords), 1)
                scored_results.append((suite, score, data))
        
        # Also search in category
        for suite, data in self.search_index.items():
            if query.lower() in data["category"].lower():
                if not any(s[0] == suite for s in scored_results):
                    scored_results.append((suite, 0.8, data))
        
        # Also search for keyword in module names
        for suite, data in self.search_index.items():
            modules = data["modules"]
            for module in modules:
                if query.lower() in module.lower():
                    if not any(s[0] == suite for s in scored_results):
                        scored_results.append((suite, 0.85, data))
                    break
        
        # Sort by score
        scored_results.sort(key=lambda x: x[1], reverse=True)
        
        results = []
        for suite, score, data in scored_results[:limit]:
            results.append({
                "suite": suite,
                "modules": data["modules"],
                "description": data["description"],
                "category": data["category"],
                "score": score,
                "match_type": "keyword"
            })
        
        return results
    
    def search_by_category(self, category: str, limit: int = 100) -> List[Dict]:
        """Search for all tools in a specific category."""
        results = []
        
        for suite, data in self.search_index.items():
            if category.lower() in data["category"].lower():
                results.append({
                    "suite": suite,
                    "modules": data["modules"],
                    "description": data["description"],
                    "category": data["category"],
                    "score": 1.0,
                    "match_type": "category"
                })
        
        return results[:limit]
    
    def search_external_tools(self, query: str, limit: int = 10) -> List[Dict]:
        """Search for tools that integrate with specific external tools."""
        candidates = []
        
        for suite, data in self.search_index.items():
            external_tools = data.get("external_tools", [])
            for ext_tool in external_tools:
                if query.lower() in ext_tool.lower():
                    candidates.append({
                        "suite": suite,
                        "modules": data["modules"],
                        "external_tool": ext_tool,
                        "description": data["description"],
                        "score": 0.9
                    })
        
        return candidates[:limit]
    
    def search(self, query: str, search_type: str = "auto", limit: int = 10) -> List[Dict]:
        """
        Unified search across multiple search methods.
        
        search_type options:
        - "auto": Try name first, then keyword, then category
        - "name": Search by suite/module name
        - "keyword": Search by functionality
        - "category": Search by category
        - "external": Search by external tool integration
        """
        if search_type == "auto":
            # Try name match first
            results = self.search_by_name(query, limit)
            if results:
                return results
            
            # Then keyword match
            results = self.search_by_keyword(query, limit)
            if results:
                return results
            
            # Then category match
            results = self.search_by_category(query, limit)
            if results:
                return results
            
            return []
        
        elif search_type == "name":
            return self.search_by_name(query, limit)
        
        elif search_type == "keyword":
            return self.search_by_keyword(query, limit)
        
        elif search_type == "category":
            return self.search_by_category(query, limit)
        
        elif search_type == "external":
            return self.search_external_tools(query, limit)
        
        else:
            raise ValueError(f"Unknown search_type: {search_type}")
    
    def get_tool_command(self, suite: str, module: Optional[str] = None) -> str:
        """Generate the command to run a tool."""
        if module:
            return f"{suite} {module}"
        else:
            # If suite has only one module, return just the suite name
            if suite in self.registry and len(self.registry[suite]["modules"]) == 1:
                return suite
            return f"{suite}"
    
    def get_related_tools(self, suite: str) -> List[Dict]:
        """Get tools that are related to the given suite."""
        if suite not in self.relationships:
            return []
        
        related = self.relationships[suite].get("related_tools", {})
        results = []
        
        for relation_type, tools in related.items():
            for tool in tools:
                # Try to find this tool in our registry
                for suite_name, data in self.search_index.items():
                    if tool.lower() in suite_name.lower():
                        results.append({
                            "suite": suite_name,
                            "modules": data["modules"],
                            "relation": relation_type,
                            "score": 0.95
                        })
                        break
        
        return results
    
    def display_results(self, results: List[Dict], title: str = "Search Results") -> None:
        """Display search results in a formatted table."""
        if not results:
            console.print(f"[yellow]No results found for your search.[/yellow]")
            return
        
        table = Table(title=f"[bold cyan]{title}[/bold cyan]", show_header=True, header_style="bold magenta")
        table.add_column("Suite", style="cyan")
        table.add_column("Modules", style="yellow")
        table.add_column("Description", style="white")
        table.add_column("Category", style="green")
        table.add_column("Match Score", style="magenta")
        
        for result in results:
            modules = ", ".join(result["modules"])
            score_pct = f"{result.get('score', 0.0) * 100:.0f}%"
            table.add_row(
                result["suite"],
                modules,
                result["description"][:40],
                result["category"],
                score_pct
            )
        
        console.print(table)
    
    def print_tool_details(self, suite: str) -> None:
        """Print detailed information about a tool."""
        if suite not in self.registry:
            console.print(f"[red]Tool '{suite}' not found.[/red]")
            return
        
        data = self.registry[suite]
        
        console.print(f"\n[bold cyan]╔═══ {suite.upper()} ═══╗[/bold cyan]")
        console.print(f"[bold yellow]Description:[/bold yellow] {data.get('description', 'N/A')}")
        console.print(f"[bold yellow]Category:[/bold yellow] {data.get('category', 'N/A')}")
        
        modules = data.get('modules', [])
        console.print(f"[bold yellow]Modules:[/bold yellow]")
        for mod in modules:
            console.print(f"  • {mod}")
        
        external = data.get('external_tools', {})
        if external:
            console.print(f"[bold yellow]Integrated External Tools:[/bold yellow]")
            for ext_tool, desc in external.items():
                console.print(f"  • {ext_tool}: {desc}")
        
        # Show related tools
        related = self.get_related_tools(suite)
        if related:
            console.print(f"[bold yellow]Related Tools:[/bold yellow]")
            for rel in related:
                console.print(f"  • {rel['suite']} ({rel['relation']})")
        
        console.print(f"[bold cyan]╚{'═' * (len(suite) + 10)}╝[/bold cyan]\n")


def quick_launch(query: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Quick launch a tool by partial name.
    Returns (suite, module) tuple or (None, None) if not found.
    """
    searcher = ToolSearcher()
    results = searcher.search(query, search_type="auto", limit=5)
    
    if not results:
        return None, None
    
    # If only one result, use it
    if len(results) == 1:
        result = results[0]
        suite = result["suite"]
        modules = result["modules"]
        
        # If suite has only one module, auto-select it
        if len(modules) == 1:
            return suite, modules[0]
        else:
            # Return suite without module; caller will need to choose
            return suite, None
    
    # Multiple results; return the best match
    best = results[0]
    suite = best["suite"]
    modules = best["modules"]
    
    if len(modules) == 1:
        return suite, modules[0]
    else:
        return suite, None


def print_search_help() -> None:
    """Print help for the search/find command."""
    help_text = """
[bold cyan]SEARCH & DISCOVERY COMMANDS[/bold cyan]

[bold yellow]find <query>[/bold yellow]
  Fuzzy search for tools by name or keyword
  Examples:
    • [cyan]find sql[/cyan]         → Find SQL-related tools
    • [cyan]find kerb[/cyan]        → Find Kerberos tools
    • [cyan]find recon[/cyan]       → Find reconnaissance tools

[bold yellow]find -k <query>[/bold yellow]
  Search by functionality/keyword
  Examples:
    • [cyan]find -k "password spraying"[/cyan]
    • [cyan]find -k "web exploitation"[/cyan]

[bold yellow]find -c <category>[/bold yellow]
  Search by category
  Examples:
    • [cyan]find -c "Offensive Security"[/cyan]
    • [cyan]find -c "Infrastructure"[/cyan]

[bold yellow]find -e <tool>[/bold yellow]
  Find tools that integrate with external tools
  Examples:
    • [cyan]find -e sqlmap[/cyan]
    • [cyan]find -e metasploit[/cyan]

[bold yellow]info <suite>[/bold yellow]
  Display detailed information about a tool
  Examples:
    • [cyan]info spekt[/cyan]
    • [cyan]info kerb[/cyan]

[bold yellow]run <query>[/bold yellow]
  Quick-launch a tool by partial name
  Examples:
    • [cyan]run sql[/cyan]    → Launch webpwn/sqlix
    • [cyan]run kerb[/cyan]   → Launch kerb/tixr
    • [cyan]run recon[/cyan]  → Launch wraith/recon

[bold yellow]relate <suite>[/bold yellow]
  Show tools related to the given tool
  Examples:
    • [cyan]relate webpwn[/cyan]
    • [cyan]relate spekt[/cyan]
"""
    console.print(help_text)
