from rich.console import Console
from utils.banner import print_nox_banner

console = Console()

# --- Identity ---
TOOL_NAME = "NETPWN"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Network Infrastructure Attack Suite"

# --- Banner Config ---
BORDER = "dodger_blue2"
NAME_COLOR = "bold dodger_blue2"
FILL_COLOR = "navy_blue"
TAG_COLOR = "cornflower_blue"
FCHAR = "≡"

# Using 'big' font
ART_LINES = [
    "  _   _ ______ _______ _______          ___   _ ",
    " | \\ | |  ____|__   __|  __ \\ \\        / / \\ | |",
    " |  \\| | |__     | |  | |__) \\ \\  /\\  / /|  \\| |",
    " | . ` |  __|    | |  |  ___/ \\ \\/  \\/ / | . ` |",
    " | |\\  | |____   | |  | |      \\  /\\  /  | |\\  |",
    " |_| \\_|______|  |_|  |_|       \\/  \\/   |_| \\_|"
]

def main():
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)
    console.print(f"[*] {TOOL_NAME} module initialized.")

if __name__ == "__main__":
    main()
