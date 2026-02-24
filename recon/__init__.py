from rich.console import Console
from utils.banner import print_nox_banner

console = Console()

# --- Identity ---
TOOL_NAME = "RECON"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Active Reconnaissance Suite"

# --- Banner Config ---
BORDER = "bright_cyan"
NAME_COLOR = "bold bright_cyan"
FILL_COLOR = "dark_cyan"
TAG_COLOR = "light_cyan3"
FCHAR = "∙"

# Using 'big' font as it fits 'RECON' well
ART_LINES = [
    " _____  ______ _____ ____  _   _ ",
    "|  __ \\|  ____/ ____/ __ \\| \\ | |",
    "| |__) | |__ | |   | |  | |  \\| |",
    "|  _  /|  __|| |   | |  | | . ` |",
    "| | \\ \\| |___| |___| |__| | |\\  |",
    "|_|  \\_\\______\\_____\\____/|_| \\_|"
]

def main():
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)
    console.print(f"[*] {TOOL_NAME} module initialized.")

if __name__ == "__main__":
    main()
