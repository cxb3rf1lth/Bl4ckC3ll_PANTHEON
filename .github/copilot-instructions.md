# Bl4ckC3ll_PANTHEON V2.0.0 - GitHub Copilot Instructions

**ALWAYS follow these instructions first and only fallback to additional search and context gathering if the information in these instructions is incomplete or found to be in error.**

## Working Effectively

### Bootstrap, Build, and Test the Repository
Execute these commands in exact order - **NEVER CANCEL any long-running commands**:

```bash
# 1. Install system dependencies (required for Go tools)
sudo apt-get update && sudo apt-get install -y libpcap-dev build-essential

# 2. Run automated installation - TAKES 10+ MINUTES, NEVER CANCEL
timeout 1200 ./install.sh  # Set timeout to 20+ minutes minimum

# 3. Install Go security tools - TAKES 7+ MINUTES, NEVER CANCEL  
export PATH=$HOME/go/bin:$PATH
timeout 600 make tools  # Set timeout to 10+ minutes minimum

# 4. Install Node.js dependencies for linting
npm install  # Takes ~5 seconds

# 5. Set PATH permanently for current session
echo 'export PATH=$HOME/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### Test Installation and Functionality
```bash
# Validate installation (takes ~2 seconds)
python3 diagnostics.py

# Run comprehensive test suite - TAKES 60+ SECONDS, NEVER CANCEL
timeout 180 python3 comprehensive_test_suite.py  # Set timeout to 3+ minutes

# Run enhanced features test (takes ~0.3 seconds)
python3 test_enhanced_features.py
```

### Run the Application
```bash
# ALWAYS run the bootstrapping steps first
# Ensure targets.txt exists
echo "example.com" > targets.txt

# Start the main application
export PATH=$HOME/go/bin:$PATH
python3 bl4ckc3ll_p4nth30n.py
```

## Validation

### Manual Validation Scenarios
**ALWAYS test these complete user scenarios after making changes:**

1. **Installation Validation Scenario:**
   ```bash
   # Test complete fresh setup
   ./quickstart.sh  # TAKES 10+ MINUTES, NEVER CANCEL
   python3 diagnostics.py  # Should show "Installation looks good!"
   ```

2. **Basic Reconnaissance Scenario:**
   ```bash
   # Start application and test menu option 3 (Enhanced Reconnaissance)
   python3 bl4ckc3ll_p4nth30n.py
   # Select option 3, then wait for completion - TAKES 5+ MINUTES
   ```

3. **Test Suite Validation Scenario:**
   ```bash
   # Run all test suites - NEVER CANCEL
   timeout 300 python3 comprehensive_test_suite.py  # 96.6% pass rate expected
   python3 test_enhanced_features.py  # 5/6 tests should pass
   ```

4. **Linting and Code Quality Scenario:**
   ```bash
   npm run lint  # Takes ~0.5 seconds
   npm run test  # Takes ~1 second
   ```

### Build and Test Timing Expectations
- **Installation (install.sh):** 9-10 minutes - **NEVER CANCEL, SET TIMEOUT TO 20+ MINUTES**
- **Go tools (make tools):** 6-7 seconds after libpcap-dev - **NEVER CANCEL, SET TIMEOUT TO 10+ MINUTES**  
- **Comprehensive test suite:** 58-60 seconds - **NEVER CANCEL, SET TIMEOUT TO 3+ MINUTES**
- **Enhanced features test:** 0.3 seconds
- **Diagnostics check:** 2 seconds
- **NPM install:** 4-5 seconds
- **Linting:** 0.5 seconds
- **Application startup:** 3 seconds

## Critical Dependencies and Requirements

### Exact System Requirements
- **OS:** Linux (Ubuntu 20.04+ recommended)
- **Python:** 3.9+ (3.12+ recommended) - `python3 -V` to check
- **Go:** 1.20+ - auto-installed by install.sh if missing
- **Node.js:** 18.0+ for ESLint security checks
- **Memory:** 4GB+ RAM minimum
- **Disk:** 2GB+ free space for tools and results

### Critical PATH Configuration
```bash
# MUST be set for security tools to work - add to ~/.bashrc permanently
export PATH=$HOME/go/bin:$PATH
```

### Exact Installation Commands for Missing Dependencies
```bash
# System dependencies REQUIRED before Go tools
sudo apt-get install -y libpcap-dev build-essential

# If Go tools fail, install manually:
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest  
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest

# Python dependencies from requirements.txt
pip3 install -r requirements.txt --user
```

## Common Tasks and Validation Steps

### Always Run Before Committing Changes
```bash
# 1. Validate dependencies are working
python3 diagnostics.py  # Must show "Installation looks good!"

# 2. Run test suites - NEVER CANCEL
timeout 300 python3 comprehensive_test_suite.py  # Must pass 28+ tests
python3 test_enhanced_features.py  # Must pass 5+ tests

# 3. Run linting 
npm run lint  # Must complete without errors

# 4. Test basic application functionality
echo "example.com" > targets.txt
python3 bl4ckc3ll_p4nth30n.py  # Should show 28-option menu
```

### CI/CD Integration Commands
```bash
# Quick security scan for CI/CD pipelines
python3 cicd_integration.py \
  --target testphp.vulnweb.com \
  --scan-type quick \
  --output-format sarif \
  --timeout 600  # NEVER CANCEL, 10+ minute timeout minimum

# Bug bounty automation - TAKES 20+ MINUTES, NEVER CANCEL
timeout 1800 ./bug_bounty_commands.sh target.com  # 30+ minute timeout
```

## Key Projects and Components

### Core Application Files
- **bl4ckc3ll_p4nth30n.py:** Main application entry point (356KB)
- **bcar.py:** BCAR enhanced reconnaissance module (27KB)
- **cicd_integration.py:** CI/CD pipeline integration (21KB)
- **diagnostics.py:** System validation and health checks (8KB)

### Configuration and Setup
- **p4nth30n.cfg.json:** Main configuration file with 14 sections
- **requirements.txt:** Python dependencies (50 packages)
- **package.json:** Node.js dependencies for ESLint
- **Makefile:** Convenience targets for common operations

### Test Infrastructure
- **comprehensive_test_suite.py:** 29 comprehensive tests (21KB)
- **test_enhanced_features.py:** Enhanced functionality tests (11KB)
- **advanced_functionality_test.py:** Advanced feature validation (18KB)

### Key Directories
- **runs/:** Scan results and reports (created at runtime)
- **logs/:** Application logging
- **plugins/:** Extensible plugin system
- **payloads/:** Security testing payloads
- **nuclei-templates/:** Vulnerability scanning templates
- **wordlists_extra/:** Additional wordlists for fuzzing

## Troubleshooting Common Issues

### "Tools not found" Errors
```bash
# Check PATH configuration
echo $PATH | grep -q "$HOME/go/bin" || echo "PATH missing $HOME/go/bin"

# Re-export PATH
export PATH=$HOME/go/bin:$PATH

# Verify tools installation
which subfinder nuclei httpx naabu katana gau
```

### "Import errors" in Python
```bash
# Reinstall Python dependencies
pip3 install -r requirements.txt --user --force-reinstall
```

### "Go tools compilation failed"
```bash
# Install missing system dependency
sudo apt-get install -y libpcap-dev

# Retry Go tools installation
export PATH=$HOME/go/bin:$PATH
make tools
```

### "ESLint not found"
```bash
# Install Node.js dependencies
npm install
```

## Application Usage Patterns

### Menu Navigation (28 Options)
The application provides 28 menu options grouped by functionality:
- **Options 1-10:** Core operations (target management, reconnaissance, vulnerability scanning)
- **Options 11-23:** Advanced features (AI analysis, cloud security, compliance)
- **Options 24-27:** BCAR enhanced capabilities (subdomain takeover, payload injection)
- **Option 28:** Exit

### Recommended First-Run Sequence
1. Option 1: Enhanced Target Management (add authorized targets)
2. Option 2: Refresh Sources + Merge Wordlists
3. Option 3: Enhanced Reconnaissance - **TAKES 5+ MINUTES, NEVER CANCEL**
4. Option 4: Advanced Vulnerability Scan - **TAKES 10+ MINUTES, NEVER CANCEL** 
5. Option 7: Generate Enhanced Report

### Results and Output
- **runs/YYYYMMDD_HHMMSS_ID/:** Individual scan results
- **runs/*/report/:** HTML, JSON, and CSV reports
- **logs/:** Application logs and debugging information

## Security and Legal Compliance

**CRITICAL:** This framework is designed for authorized security assessments only. Always ensure you have explicit permission to test any targets. The application includes safety modes and test configurations to prevent accidental execution against unauthorized targets.

**Test Mode Usage:**
```bash
# Always test changes with safe targets first
echo "testphp.vulnweb.com" > targets.txt  # Authorized test target
```

## Performance and Resource Management

### Expected Resource Usage
- **Memory:** 4-8GB during full scans
- **CPU:** High usage during reconnaissance and vulnerability scanning phases
- **Network:** Moderate outbound traffic to target systems
- **Disk:** 1-2GB for results and temporary files per large scan

### Optimization Settings
The application includes built-in resource monitoring and throttling. Monitor system resources during large scans and adjust concurrency settings in p4nth30n.cfg.json if needed.