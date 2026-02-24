from rich.console import Console

console = Console()

def print_nox_banner(tool_name: str, version: str, description: str, 
                     border_color: str, name_color: str, fill_color: str, 
                     fill_char: str, tagline_color: str, art_lines: list) -> None:
    """
    Generic banner printer following Nox standards.
    """
    W = 59
    fill = fill_char * W
    label = f"[ {tool_name.lower()} v{version} ]"
    hdr = f"≺ RAVEN-SECURITY // NOX ≻{label:>{W - 25}}"
    
    WARN = "bold yellow"
    HEAD = "grey58"

    console.print(f"[{border_color}]  ┌{'─' * W}┐[/{border_color}]")
    console.print(f"[{HEAD}]  │  {hdr}  │[/{HEAD}]")
    console.print(f"[{border_color}]  ├{'╌' * W}┤[/{border_color}]")
    console.print(f"[{border_color}]  │{' ' * (W + 2)}│[/{border_color}]")
    console.print(f"[{fill_color}]  │  {fill}  │[/{fill_color}]")
    console.print(f"[{border_color}]  │{' ' * (W + 2)}│[/{border_color}]")

    for line in art_lines:
        pad = W + 2 - len(line)
        console.print(f"[{name_color}]  │{line}{' ' * pad}│[/{name_color}]")

    console.print(f"[{border_color}]  │{' ' * (W + 2)}│[/{border_color}]")
    console.print(f"[{fill_color}]  │  {fill}  │[/{fill_color}]")
    console.print(f"[{border_color}]  │{' ' * (W + 2)}│[/{border_color}]")
    
    desc_pad = W - len(description)
    console.print(f"[{tagline_color}]  │    {description}{' ' * desc_pad}│[/{tagline_color}]")
    
    console.print(f"[{border_color}]  ├{'╌' * W}┤[/{border_color}]")
    console.print(f"[{WARN}]  │  ⚠  Authorized use only.  Raven-Security © 2025{' ' * (W - 47)}│[/{WARN}]")
    console.print(f"[{border_color}]  └{'─' * W}┘[/{border_color}]")
    console.print()
