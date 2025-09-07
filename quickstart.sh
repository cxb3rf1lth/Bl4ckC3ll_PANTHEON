#!/bin/bash
# Bl4ckC3ll_PANTHEON Quick Start Script
# This script provides a streamlined way to get started quickly

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Bl4ckC3ll_PANTHEON Quick Start${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if already set up
if [[ -f ".setup_complete" ]]; then
    echo -e "${GREEN}Setup already completed!${NC}"
    echo ""
    echo "Running Bl4ckC3ll_PANTHEON..."
    python3 bl4ckc3ll_p4nth30n.py
    exit 0
fi

echo -e "${BLUE}Step 1:${NC} Checking Python version..."
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" 2>/dev/null; then
    PYTHON_VERSION=$(python3 -V)
    echo -e "${GREEN}✓${NC} $PYTHON_VERSION detected"
else
    echo -e "${YELLOW}Python 3.9+ required. Please install Python 3.9 or newer and try again.${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Step 2:${NC} Running automated setup..."
echo "This will install dependencies and security tools..."
echo ""

# Run the installer
if ./install.sh; then
    echo ""
    echo -e "${GREEN}✓ Setup completed successfully!${NC}"
    touch .setup_complete
else
    echo -e "${YELLOW}Setup completed with some warnings. Continuing...${NC}"
fi

echo ""
echo -e "${BLUE}Step 3:${NC} Testing installation..."
if python3 test_installation.py; then
    echo -e "${GREEN}✓ Installation test passed!${NC}"
else
    echo -e "${YELLOW}Some tests failed, but continuing...${NC}"
fi

echo ""
echo -e "${BLUE}Step 4:${NC} Creating example targets..."
if [[ ! -s "targets.txt" ]]; then
    echo "example.com" > targets.txt
    echo -e "${GREEN}✓ Created targets.txt with example.com${NC}"
else
    echo -e "${GREEN}✓ targets.txt already exists${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Quick start complete!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Edit targets.txt to add your authorized targets"
echo "2. Run: python3 bl4ckc3ll_p4nth30n.py"
echo "3. Select options 2, 3, 4, 5 for a full scan"
echo ""
echo "Starting Bl4ckC3ll_PANTHEON now..."
echo ""

# Source shell profile to get updated PATH
if [[ -f "$HOME/.bashrc" ]]; then
    source "$HOME/.bashrc" 2>/dev/null || true
fi

python3 bl4ckc3ll_p4nth30n.py