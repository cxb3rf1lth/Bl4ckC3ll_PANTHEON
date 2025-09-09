#!/bin/bash
# Bl4ckC3ll_PANTHEON Consolidated TUI Installation Script
# Advanced Security Testing Framework - Complete Installation

set -e

echo "🚀 Bl4ckC3ll PANTHEON - Advanced Security Testing Framework"
echo "=================================================================="
echo "🔧 Installing Consolidated TUI Application..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

# Check Python version
print_step "Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [[ $PYTHON_MAJOR -ge 3 && $PYTHON_MINOR -ge 9 ]]; then
        print_status "Python $PYTHON_VERSION found ✓"
    else
        print_error "Python 3.9+ required, found $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 not found. Please install Python 3.9+"
    exit 1
fi

# Check if pip is available
print_step "Checking pip..."
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 not found. Installing pip..."
    python3 -m ensurepip --upgrade
fi

# Install Python dependencies
print_step "Installing Python dependencies..."
pip3 install --user --upgrade pip

# Core dependencies
print_status "Installing core TUI dependencies..."
pip3 install --user textual psutil requests beautifulsoup4 lxml

# Optional advanced dependencies
print_status "Installing advanced dependencies..."
pip3 install --user --ignore-errors numpy pandas scikit-learn matplotlib plotly jinja2 || print_warning "Some advanced packages failed to install (optional)"

# Network analysis dependencies
pip3 install --user --ignore-errors python-nmap netaddr urllib3 pycryptodome || print_warning "Some network packages failed to install (optional)"

# Cloud security dependencies
pip3 install --user --ignore-errors boto3 azure-storage-blob google-cloud-storage || print_warning "Cloud packages failed to install (optional)"

# Additional utilities
pip3 install --user --ignore-errors jsonschema pyyaml colorama tqdm pytest || print_warning "Some utility packages failed to install (optional)"

# Check Go installation for external tools
print_step "Checking Go installation..."
if command -v go &> /dev/null; then
    print_status "Go found ✓"
    
    # Install security tools
    print_step "Installing security tools..."
    export PATH="$HOME/go/bin:$PATH"
    
    # ProjectDiscovery tools
    print_status "Installing ProjectDiscovery tools..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || print_warning "subfinder install failed"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || print_warning "httpx install failed"
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || print_warning "naabu install failed"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || print_warning "nuclei install failed"
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest || print_warning "katana install failed"
    
    # Additional tools
    print_status "Installing additional tools..."
    go install -v github.com/lc/gau/v2/cmd/gau@latest || print_warning "gau install failed"
    go install -v github.com/tomnomnom/waybackurls@latest || print_warning "waybackurls install failed"
    go install -v github.com/ffuf/ffuf@latest || print_warning "ffuf install failed"
    
else
    print_warning "Go not found. Some external tools will not be available."
    print_status "To install Go: https://golang.org/doc/install"
fi

# Check system tools
print_step "Checking system tools..."
TOOLS=("curl" "wget" "dig" "nmap" "git")
for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        print_status "$tool found ✓"
    else
        print_warning "$tool not found (recommended)"
    fi
done

# Create necessary directories
print_step "Creating directories..."
mkdir -p runs logs backups external_lists lists_merged bcar_results payloads plugins exploits wordlists_extra

# Set up configuration
print_step "Setting up configuration..."
if [[ ! -f "p4nth30n.cfg.json" ]]; then
    cat > p4nth30n.cfg.json << 'EOF'
{
  "limits": {
    "parallel_jobs": 20,
    "http_timeout": 15,
    "rps": 500,
    "max_concurrent_scans": 8,
    "http_revalidation_timeout": 8
  },
  "nuclei": {
    "enabled": true,
    "severity": "low,medium,high,critical",
    "rps": 800,
    "conc": 150,
    "all_templates": true,
    "keep_info_severity": false
  },
  "endpoints": {
    "use_gau": true,
    "use_katana": true,
    "max_urls_per_target": 5000,
    "katana_depth": 2
  },
  "report": {
    "formats": ["html", "json", "csv"],
    "auto_open_html": false,
    "include_viz": true
  },
  "tui": {
    "theme": "dark",
    "auto_refresh": true,
    "refresh_interval": 2
  }
}
EOF
    print_status "Created default configuration"
else
    print_status "Configuration file already exists"
fi

# Create sample targets file
if [[ ! -f "targets.txt" ]]; then
    cat > targets.txt << 'EOF'
# Example targets (remove these and add your own)
# testphp.vulnweb.com
# scanme.nmap.org
EOF
    print_status "Created sample targets.txt"
fi

# Set up PATH
print_step "Setting up PATH..."
if [[ ! -d "$HOME/.local/bin" ]]; then
    mkdir -p "$HOME/.local/bin"
fi

# Add to PATH if not already there
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"' >> ~/.bashrc
    print_status "Added local binaries to PATH"
fi

# Create launcher script
print_step "Creating launcher scripts..."
cat > bl4ckc3ll_pantheon << 'EOF'
#!/bin/bash
# Bl4ckC3ll_PANTHEON Launcher
cd "$(dirname "$0")"
python3 tui_consolidated.py "$@"
EOF
chmod +x bl4ckc3ll_pantheon

# Create CLI launcher
cat > bl4ckc3ll_pantheon_cli << 'EOF'
#!/bin/bash
# Bl4ckC3ll_PANTHEON CLI Launcher
cd "$(dirname "$0")"
python3 bl4ckc3ll_p4nth30n.py "$@"
EOF
chmod +x bl4ckc3ll_pantheon_cli

# Test installation
print_step "Testing installation..."
if python3 -c "import textual; import psutil; print('Core dependencies OK')" 2>/dev/null; then
    print_status "Core dependencies test passed ✓"
else
    print_error "Core dependencies test failed"
    exit 1
fi

# Test TUI import
if python3 -c "from tui_consolidated import ConsolidatedTUI; print('TUI import OK')" 2>/dev/null; then
    print_status "TUI application test passed ✓"
else
    print_error "TUI application test failed"
    exit 1
fi

# Success message
echo ""
echo "=================================================================="
echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
echo "=================================================================="
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo "  TUI Mode:  ./bl4ckc3ll_pantheon"
echo "  CLI Mode:  ./bl4ckc3ll_pantheon_cli"
echo ""
echo -e "${BLUE}Features Available:${NC}"
echo "  ✅ Advanced TUI Interface with real-time monitoring"
echo "  ✅ Target management and validation"
echo "  ✅ Multiple scan types and configurations"
echo "  ✅ Professional report generation"
echo "  ✅ System resource monitoring"
echo "  ✅ Backend integration with CLI tools"
echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "  📝 Edit p4nth30n.cfg.json for advanced settings"
echo "  🎯 Add targets to targets.txt or use TUI interface"
echo ""
echo -e "${BLUE}Documentation:${NC}"
echo "  📚 See README.md for detailed usage instructions"
echo "  🔗 Visit project repository for updates"
echo ""
echo -e "${YELLOW}Note:${NC} If PATH changes were made, restart your terminal or run:"
echo "  source ~/.bashrc"
echo ""
print_status "Ready for security testing! 🚀"