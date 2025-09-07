#!/bin/bash
# Bl4ckC3ll_PANTHEON Automated Setup Script
# Author: @cxb3rf1lth
# Purpose: Automate installation and setup of all dependencies

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   log_error "This script should not be run as root for security reasons"
   exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log_info "Starting Bl4ckC3ll_PANTHEON automated setup..."

# Check Python version
check_python() {
    log_info "Checking Python version..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [[ $PYTHON_MAJOR -ge 3 && $PYTHON_MINOR -ge 9 ]]; then
            log_success "Python $PYTHON_VERSION detected (requirement: 3.9+)"
        else
            log_error "Python 3.9+ required, found $PYTHON_VERSION"
            exit 1
        fi
    else
        log_error "Python3 not found. Please install Python 3.9 or newer"
        exit 1
    fi
}

# Upgrade pip and install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Upgrade pip
    python3 -m pip install --upgrade pip --user
    
    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        python3 -m pip install -r requirements.txt --user
        log_success "Python dependencies installed"
    else
        log_warning "requirements.txt not found, installing basic dependencies"
        python3 -m pip install psutil distro requests --user
    fi
}

# Check and install Go
install_go() {
    log_info "Checking Go installation..."
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | grep -oP 'go\d+\.\d+' | sed 's/go//')
        log_success "Go $GO_VERSION found"
    else
        log_info "Go not found. Installing Go..."
        
        # Detect architecture
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) GO_ARCH="amd64" ;;
            aarch64|arm64) GO_ARCH="arm64" ;;
            armv7l) GO_ARCH="armv6l" ;;
            *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        
        # Download and install Go
        GO_VERSION="1.21.3"
        GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        
        cd /tmp
        wget -q "https://golang.org/dl/${GO_TAR}"
        
        # Install to user directory if no sudo access
        if sudo -n true 2>/dev/null; then
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf "$GO_TAR"
            log_success "Go installed system-wide"
        else
            mkdir -p "$HOME/go-installation"
            tar -C "$HOME/go-installation" -xzf "$GO_TAR"
            echo 'export PATH=$HOME/go-installation/go/bin:$PATH' >> "$HOME/.bashrc"
            log_success "Go installed to user directory"
        fi
        
        rm -f "$GO_TAR"
        cd "$SCRIPT_DIR"
    fi
}

# Setup Go environment
setup_go_env() {
    log_info "Setting up Go environment..."
    
    # Determine Go installation path
    if command -v go &> /dev/null; then
        GO_ROOT=$(go env GOROOT)
    elif [[ -d "/usr/local/go" ]]; then
        export PATH="/usr/local/go/bin:$PATH"
    elif [[ -d "$HOME/go-installation/go" ]]; then
        export PATH="$HOME/go-installation/go/bin:$PATH"
    fi
    
    # Setup GOPATH and GOBIN
    export GOPATH="$HOME/go"
    export GOBIN="$GOPATH/bin"
    mkdir -p "$GOPATH" "$GOBIN"
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
        export PATH="$GOBIN:$PATH"
    fi
    
    # Add to shell profile for persistence
    SHELL_PROFILE=""
    if [[ -f "$HOME/.bashrc" ]]; then
        SHELL_PROFILE="$HOME/.bashrc"
    elif [[ -f "$HOME/.zshrc" ]]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [[ -f "$HOME/.profile" ]]; then
        SHELL_PROFILE="$HOME/.profile"
    fi
    
    if [[ -n "$SHELL_PROFILE" ]]; then
        if ! grep -q "GOPATH.*$HOME/go" "$SHELL_PROFILE" 2>/dev/null; then
            echo '' >> "$SHELL_PROFILE"
            echo '# Go environment' >> "$SHELL_PROFILE"
            echo 'export GOPATH="$HOME/go"' >> "$SHELL_PROFILE"
            echo 'export GOBIN="$GOPATH/bin"' >> "$SHELL_PROFILE"
            echo 'export PATH="$GOBIN:$HOME/.local/bin:/usr/local/bin:$PATH"' >> "$SHELL_PROFILE"
            log_success "Go environment added to $SHELL_PROFILE"
        fi
    fi
    
    log_success "Go environment configured"
}

# Install Go-based security tools
install_go_tools() {
    log_info "Installing Go-based security tools..."
    
    # Ensure Go is available
    if ! command -v go &> /dev/null; then
        log_error "Go not available in PATH"
        exit 1
    fi
    
    # List of tools to install
    declare -A tools=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
    )
    
    for tool in "${!tools[@]}"; do
        log_info "Installing $tool..."
        if go install "${tools[$tool]}"; then
            log_success "$tool installed successfully"
        else
            log_warning "Failed to install $tool, continuing..."
        fi
    done
    
    # Update nuclei templates
    if command -v nuclei &> /dev/null; then
        log_info "Updating Nuclei templates..."
        nuclei -update-templates || log_warning "Failed to update Nuclei templates"
    fi
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    directories=(
        "runs"
        "logs"
        "external_lists"
        "lists_merged"
        "payloads"
        "exploits"
        "plugins"
        "backups"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done
    
    log_success "Directory structure created"
}

# Validate installation
validate_installation() {
    log_info "Validating installation..."
    
    # Check Python script
    if [[ -f "bl4ckc3ll_p4nth30n.py" ]]; then
        log_success "Main script found: bl4ckc3ll_p4nth30n.py"
    else
        log_error "Main script not found"
        exit 1
    fi
    
    # Check configuration
    if [[ -f "p4nth30n.cfg.json" ]]; then
        log_success "Configuration file found"
    else
        log_warning "Configuration file not found, will be created on first run"
    fi
    
    # Check targets file
    if [[ -f "targets.txt" ]]; then
        log_success "Targets file found"
    else
        log_warning "Creating default targets.txt with example.com"
        echo "example.com" > targets.txt
    fi
    
    # Check installed tools
    tools_found=0
    total_tools=6
    
    for tool in subfinder httpx naabu nuclei katana gau; do
        if command -v "$tool" &> /dev/null; then
            log_success "$tool is available"
            ((tools_found++))
        else
            log_warning "$tool not found in PATH"
        fi
    done
    
    log_info "Found $tools_found/$total_tools security tools"
    
    if [[ $tools_found -eq 0 ]]; then
        log_warning "No security tools found. The script will work but with limited functionality."
    fi
}

# Create a quick test script
create_test_script() {
    log_info "Creating test script..."
    
    cat > test_installation.py << 'EOF'
#!/usr/bin/env python3
"""Test script to validate Bl4ckC3ll_PANTHEON installation"""

import sys
import subprocess
import shutil
from pathlib import Path

def test_python_deps():
    """Test Python dependencies"""
    try:
        import psutil
        import distro
        print("✓ Python dependencies available")
        return True
    except ImportError as e:
        print(f"✗ Python dependency missing: {e}")
        return False

def test_go_tools():
    """Test Go tools availability"""
    tools = ['subfinder', 'httpx', 'naabu', 'nuclei', 'katana', 'gau']
    available = []
    
    for tool in tools:
        if shutil.which(tool):
            available.append(tool)
    
    print(f"✓ {len(available)}/{len(tools)} Go tools available: {', '.join(available)}")
    return len(available) > 0

def test_main_script():
    """Test main script syntax"""
    try:
        result = subprocess.run([sys.executable, '-m', 'py_compile', 'bl4ckc3ll_p4nth30n.py'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Main script syntax is valid")
            return True
        else:
            print(f"✗ Main script syntax error: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error testing main script: {e}")
        return False

if __name__ == "__main__":
    print("Testing Bl4ckC3ll_PANTHEON installation...\n")
    
    tests = [
        test_python_deps,
        test_go_tools, 
        test_main_script
    ]
    
    passed = 0
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"Tests passed: {passed}/{len(tests)}")
    
    if passed == len(tests):
        print("🎉 Installation appears to be successful!")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed. Check the output above.")
        sys.exit(1)
EOF
    
    chmod +x test_installation.py
    log_success "Test script created: test_installation.py"
}

# Main installation flow
main() {
    log_info "Bl4ckC3ll_PANTHEON Automated Setup"
    log_info "=================================="
    
    check_python
    install_python_deps
    install_go
    setup_go_env
    install_go_tools
    create_directories
    create_test_script
    validate_installation
    
    echo ""
    log_success "Setup completed successfully!"
    echo ""
    log_info "Next steps:"
    echo "  1. Source your shell profile or restart your terminal:"
    echo "     source ~/.bashrc  # or ~/.zshrc"
    echo ""
    echo "  2. Test the installation:"
    echo "     python3 test_installation.py"
    echo ""
    echo "  3. Run the main script:"
    echo "     python3 bl4ckc3ll_p4nth30n.py"
    echo ""
    log_info "For troubleshooting, check the generated test_installation.py script"
}

# Run main function
main "$@"