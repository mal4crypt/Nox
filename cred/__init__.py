from rich.console import Console
from utils.banner import print_nox_banner

console = Console()

# --- Identity ---
TOOL_NAME = "CRED"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Credential Attack Suite"

# --- Banner Config ---
BORDER = "red1"
NAME_COLOR = "bold red1"
FILL_COLOR = "dark_red"
TAG_COLOR = "indian_red"
FCHAR = "×"

# Using 'big' font
ART_LINES = [
    "   _____ _____  ______ _____ ",
    "  / ____|  __ \\|  ____|  __ \\",
    " | |    | |__) | |__  | |  | |",
    " | |    |  _  /|  __| | |  | |",
    " | |____| | \\ \\| |____| |__| |",
    "  \\_____|_|  \\_\\______|_____/"
]

def main():
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)
    console.print(f"[*] {TOOL_NAME} module initialized.")

if __name__ == "__main__":
    main()
