from rich.console import Console
from utils.banner import print_nox_banner

console = Console()

# --- Identity ---
TOOL_NAME = "WEBPWN"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "Web Application Attack Suite"

# --- Banner Config ---
BORDER = "orange_red1"
NAME_COLOR = "bold orange_red1"
FILL_COLOR = "dark_red"
TAG_COLOR = "light_salmon3"
FCHAR = "▸"

# Using 'big' font
ART_LINES = [
    " __          ________ ____  _______          ___   _ ",
    " \\ \\        / /  ____|  _ \\|  __ \\ \\        / / \\ | |",
    "  \\ \\  /\\  / /| |__  | |_) | |__) \\ \\  /\\  / /|  \\| |",
    "   \\ \\/  \\/ / |  __| |  _ <|  ___/ \\ \\/  \\/ / | . ` |",
    "    \\  /\\  /  | |____| |_) | |      \\  /\\  /  | |\\  |",
    "     \\/  \\/   |______|____/|_|       \\/  \\/   |_| \\_|"
]

def main():
    print_nox_banner(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, BORDER, NAME_COLOR, FILL_COLOR, FCHAR, TAG_COLOR, ART_LINES)
    console.print(f"[*] {TOOL_NAME} module initialized.")

if __name__ == "__main__":
    main()
