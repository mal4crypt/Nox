#!/bin/bash

################################################################################
#                    NOX Framework - System Installation                       #
#                                                                              #
# This script installs NOX as a system-wide command, allowing you to use:     #
#   nox <suite> <module> <options>                                            #
#                                                                              #
# Instead of:                                                                 #
#   python3 /path/to/nox ...                                                  #
#                                                                              #
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOX_HOME="$SCRIPT_DIR"
NOX_EXECUTABLE="$NOX_HOME/nox"

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  NOX Framework - System Installation & Setup${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}\n"

# Step 1: Verify Python 3 is installed
echo -e "${YELLOW}[*]${NC} Checking Python 3 installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[✗]${NC} Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}[✓]${NC} Found Python 3: $PYTHON_VERSION"

# Step 2: Verify nox executable exists
echo -e "\n${YELLOW}[*]${NC} Verifying NOX executable..."
if [ ! -f "$NOX_EXECUTABLE" ]; then
    echo -e "${RED}[✗]${NC} NOX executable not found at $NOX_EXECUTABLE"
    exit 1
fi

if [ ! -x "$NOX_EXECUTABLE" ]; then
    echo -e "${YELLOW}[!]${NC} Making NOX executable..."
    chmod +x "$NOX_EXECUTABLE"
fi
echo -e "${GREEN}[✓]${NC} NOX executable found and is executable"

# Step 3: Install system-wide symlink
echo -e "\n${YELLOW}[*]${NC} Installing NOX as system command..."

# Common installation directories (in priority order)
INSTALL_DIRS=("$HOME/.local/bin" "/usr/local/bin" "/usr/bin" "/opt/bin")
INSTALL_DIR=""

for dir in "${INSTALL_DIRS[@]}"; do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        INSTALL_DIR="$dir"
        break
    fi
done

if [ -z "$INSTALL_DIR" ]; then
    # Try to create ~/.local/bin if it doesn't exist
    if mkdir -p "$HOME/.local/bin" 2>/dev/null; then
        INSTALL_DIR="$HOME/.local/bin"
    else
        echo -e "${RED}[✗]${NC} No writable installation directory found."
        echo -e "\n${YELLOW}Options:${NC}"
        echo -e "  1. Run: ${BLUE}sudo $0${NC}"
        echo -e "  2. Or manually create ~/.local/bin: ${BLUE}mkdir -p ~/.local/bin${NC}"
        exit 1
    fi
fi

# Create the wrapper script
WRAPPER_SCRIPT="$INSTALL_DIR/nox"

cat > "$WRAPPER_SCRIPT" << 'EOF'
#!/bin/bash
# NOX Framework Wrapper Script
# This wrapper allows running: nox <suite> <module> <options>
# Instead of: python3 /path/to/nox ...

NOX_HOME="INSTALL_NOX_HOME"

if [ ! -f "$NOX_HOME/nox" ]; then
    echo "Error: NOX installation directory not found at $NOX_HOME"
    exit 1
fi

# Execute NOX with all arguments
python3 "$NOX_HOME/nox" "$@"
EOF

chmod +x "$WRAPPER_SCRIPT"
echo -e "${GREEN}[✓]${NC} Installed NOX wrapper to $WRAPPER_SCRIPT"

# Replace the placeholder with actual path
sed -i "s|INSTALL_NOX_HOME|$NOX_HOME|g" "$WRAPPER_SCRIPT"

# Step 4: Install requirements
echo -e "\n${YELLOW}[*]${NC} Checking Python dependencies..."
if [ -f "$NOX_HOME/requirements.txt" ]; then
    if python3 -c "import rich" 2>/dev/null; then
        echo -e "${GREEN}[✓]${NC} All required Python packages are installed"
    else
        echo -e "${YELLOW}[!]${NC} Installing required Python packages..."
        pip3 install -r "$NOX_HOME/requirements.txt" --quiet
        echo -e "${GREEN}[✓]${NC} Python packages installed"
    fi
fi

# Step 5: Verify installation
echo -e "\n${YELLOW}[*]${NC} Verifying installation..."
if command -v nox &> /dev/null; then
    NOX_VERSION=$(python3 "$NOX_HOME/nox" --version 2>/dev/null || echo "Unknown")
    echo -e "${GREEN}[✓]${NC} NOX is now installed and accessible as 'nox' command"
    echo -e "${GREEN}[✓]${NC} Version: $NOX_VERSION"
else
    echo -e "${RED}[✗]${NC} Installation verification failed"
    exit 1
fi

# Step 6: Setup shell configuration
echo -e "\n${YELLOW}[*]${NC} Configuring shell environment..."

# Determine which shell config to update
if [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC=""
fi

if [ -n "$SHELL_RC" ] && ! grep -q "NOX_HOME" "$SHELL_RC"; then
    echo -e "\n# NOX Framework Configuration" >> "$SHELL_RC"
    echo "export NOX_HOME=\"$NOX_HOME\"" >> "$SHELL_RC"
    echo "# NOX is now available as: nox <suite> <module> <options>" >> "$SHELL_RC"
    echo -e "${GREEN}[✓]${NC} Added NOX configuration to $SHELL_RC"
fi

# Final summary
echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ NOX Installation Complete!${NC}\n"

echo -e "${YELLOW}Installation Summary:${NC}"
echo -e "  Installation Directory: ${BLUE}$NOX_HOME${NC}"
echo -e "  Wrapper Location:       ${BLUE}$WRAPPER_SCRIPT${NC}"
echo -e "  Python Version:         ${BLUE}$PYTHON_VERSION${NC}"

echo -e "\n${YELLOW}Usage:${NC}"
echo -e "  ${BLUE}nox ${GREEN}<suite> <module> [options]${NC}"

echo -e "\n${YELLOW}Examples:${NC}"
echo -e "  ${BLUE}nox spekt intel --domain example.com --all${NC}"
echo -e "  ${BLUE}nox kerb tixr --domain CONTOSO.LOCAL --kerberoast${NC}"
echo -e "  ${BLUE}nox rift s3scan --target bucket-name${NC}"
echo -e "  ${BLUE}nox --help${NC}"

echo -e "\n${YELLOW}To verify installation:${NC}"
echo -e "  ${BLUE}nox --help${NC}"

echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}\n"
