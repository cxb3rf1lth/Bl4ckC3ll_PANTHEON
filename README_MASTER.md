# Bl4ckC3ll PANTHEON MASTER
## Consolidated Advanced Security Testing Framework

[![Version](https://img.shields.io/badge/version-10.0.0--MASTER--CONSOLIDATED-blue.svg)](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Educational%2FResearch-red.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-enhanced-green.svg)](SECURITY.md)

**The Ultimate Consolidated Security Testing Framework** - A comprehensive, single-file security testing tool that combines all capabilities from the Bl4ckC3ll_PANTHEON ecosystem into one powerful, unified platform.

## 🚀 What's New in MASTER

This is the **consolidated master version** that combines **ALL** capabilities from multiple specialized tools:

- ✅ **bl4ckc3ll_p4nth30n.py** (28 security testing options)
- ✅ **bcar.py** (Advanced reconnaissance capabilities) 
- ✅ **TUI Interface** (Professional terminal interface)
- ✅ **Enhanced Scanner** (Advanced scanning engine)
- ✅ **Security Utils** (Input validation & sanitization)
- ✅ **Bug Bounty Automation** (Complete automation chain)
- ✅ **Payload Management** (Advanced payload systems)
- ✅ **CI/CD Integration** (Automated testing pipelines)

### Key Improvements

🔧 **Single File Architecture** - Everything consolidated into one executable file  
🛡️ **Enhanced Security** - Comprehensive input validation and sanitization  
🎨 **Advanced TUI** - Professional terminal interface with real-time monitoring  
🤖 **AI-Powered Analysis** - Machine learning vulnerability assessment  
☁️ **Multi-Cloud Support** - AWS, Azure, GCP security testing  
📊 **Professional Reporting** - Executive and technical reports with visualizations  

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Modes](#-usage-modes)
- [Core Capabilities](#-core-capabilities)
- [TUI Interface](#-tui-interface)
- [Security Features](#-security-features)
- [Configuration](#-configuration)
- [Examples](#-examples)
- [Requirements](#-requirements)
- [License & Disclaimer](#-license--disclaimer)

---

## ⚡ Features

### 🎯 Reconnaissance & Discovery
- **BCAR Enhanced Reconnaissance** - Certificate transparency and multi-source discovery
- **Advanced Subdomain Enumeration** - Multiple wordlists and discovery techniques
- **Subdomain Takeover Detection** - 13+ cloud service vulnerability signatures
- **Technology Stack Detection** - Comprehensive framework and CMS identification
- **OSINT Integration** - Passive intelligence gathering

### 🔍 Advanced Scanning
- **Multi-threaded Port Scanning** - Efficient and comprehensive port discovery
- **Web Technology Detection** - Framework, server, and technology fingerprinting
- **Vulnerability Assessment** - AI-powered analysis and prioritization
- **API Security Testing** - REST, GraphQL, SOAP endpoint analysis
- **Cloud Security Assessment** - AWS S3, Azure Blob, GCP Storage scanning

### 🛡️ Security & Validation
- **Input Sanitization** - Comprehensive injection attack prevention
- **Security Validation** - Domain, IP, URL, and file path validation
- **Rate Limiting** - DoS protection and responsible scanning
- **Secure Execution** - Sandboxed execution environment
- **Comprehensive Logging** - Security-aware logging with sanitization

### 🎨 User Interfaces
- **Advanced TUI** - Professional terminal interface with tabs and monitoring
- **Command Line Interface** - Complete CLI with 17 specialized modules
- **Interactive Menus** - User-friendly navigation and configuration
- **Real-time Monitoring** - Live system resource and scan progress tracking

### 📊 Reporting & Analysis
- **AI-Powered Analysis** - Machine learning vulnerability assessment
- **Professional Reports** - HTML, JSON, CSV export formats
- **Risk Assessment** - Intelligent vulnerability prioritization
- **Executive Summary** - Business-focused findings and recommendations
- **Technical Details** - In-depth technical analysis and proof of concepts

---

## 📦 Installation

### Prerequisites
- **Python 3.8+** (Required)
- **pip** package manager
- **Git** for cloning

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x bl4ckc3ll_pantheon_master.py

# Run the master tool
python3 bl4ckc3ll_pantheon_master.py
```

### Dependencies

**Core Requirements:**
```
psutil>=5.9.0          # System monitoring
textual>=0.70.0        # Advanced TUI
requests>=2.28.0       # HTTP operations
```

**Enhanced Features:**
```
numpy>=1.21.0          # AI/ML capabilities
pandas>=1.5.0          # Data analysis
scikit-learn>=1.1.0    # Machine learning
matplotlib>=3.6.0      # Visualization
plotly>=5.11.0         # Interactive charts
```

**Security & Cloud:**
```
cryptography>=3.4.8    # Encryption
boto3>=1.26.0          # AWS integration
azure-storage-blob     # Azure integration
google-cloud-storage   # GCP integration
```

---

## 🚀 Quick Start

### 1. Interactive Mode (Default)
```bash
python3 bl4ckc3ll_pantheon_master.py
```

### 2. Advanced TUI Interface
```bash
python3 bl4ckc3ll_pantheon_master.py --tui
```

### 3. Quick Target Scan
```bash
python3 bl4ckc3ll_pantheon_master.py --target example.com
```

### 4. Verbose Output
```bash
python3 bl4ckc3ll_pantheon_master.py --verbose --target example.com
```

---

## 🎛️ Usage Modes

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--help` | Show help message | `--help` |
| `--version` | Display version info | `--version` |
| `--tui` | Launch TUI interface | `--tui` |
| `--target` | Quick target scan | `--target example.com` |
| `--config` | Custom config file | `--config my_config.json` |
| `--verbose` | Enable verbose output | `--verbose` |
| `--quiet` | Minimize output | `--quiet` |

### Interactive Menu System

The master tool features a comprehensive menu system with 17 specialized modules:

```
🎯 [1]  Target Management      - Add, edit, manage scan targets
🔍 [2]  BCAR Reconnaissance    - Certificate transparency discovery
🌐 [3]  Advanced Port Scanning - Comprehensive port detection
🛡️ [4]  Technology Detection   - Framework identification
⚡ [5]  Subdomain Takeover     - Vulnerability assessment
🔒 [6]  Security Validation    - Input sanitization testing
📊 [7]  Vulnerability Assessment - AI-powered analysis
☁️ [8]  Cloud Security Testing - Multi-cloud assessment
🔗 [9]  API Security Testing   - REST/GraphQL/SOAP testing
🤖 [10] Automated Testing Chain - Complete automation
💉 [11] Payload Management     - Advanced payload systems
🎨 [12] TUI Interface          - Launch terminal interface
📈 [13] Generate Reports       - Professional reporting
⚙️ [14] Configuration          - Framework settings
🔧 [15] Tool Diagnostics       - System status check
📚 [16] Help & Documentation   - Usage guidance
🚪 [17] Exit                   - Close application
```

---

## 🎯 Core Capabilities

### BCAR Enhanced Reconnaissance

The Built-in Certificate Authority Reconnaissance (BCAR) module provides:

- **Certificate Transparency Search** - Query CT logs for subdomain discovery
- **Advanced Subdomain Enumeration** - Multi-threaded subdomain checking
- **Subdomain Takeover Detection** - 13+ cloud service signatures
- **Technology Detection** - Web framework and CMS identification

```python
# Example usage in code
bcar = BCARCore()
subdomains = bcar.certificate_transparency_search("example.com")
takeovers = bcar.subdomain_takeover_check(subdomains)
```

### Advanced Scanning Engine

Comprehensive scanning capabilities include:

- **Port Scanning** - Multi-threaded TCP port discovery
- **Service Detection** - Banner grabbing and service identification
- **Web Technology Analysis** - Framework and technology stack detection
- **SSL/TLS Analysis** - Certificate validation and configuration assessment

### Security Validation System

Enterprise-grade security features:

- **Input Sanitization** - Prevent injection attacks
- **Domain/IP Validation** - Secure target validation
- **Path Traversal Protection** - File system security
- **Rate Limiting** - DoS prevention

```python
# Security validation examples
SecurityValidator.validate_domain("example.com")    # True
SecurityValidator.validate_ip("192.168.1.1")       # True
SecurityValidator.sanitize_input("<script>alert(1)</script>")  # Safe output
```

---

## 🎨 TUI Interface

The Advanced Terminal User Interface provides a professional, real-time interface:

### Features
- **Tabbed Navigation** - Dashboard, Targets, Scanner, Reports, Settings
- **Real-time Monitoring** - CPU, Memory, Disk usage
- **Interactive Tables** - Target management and results display
- **Progress Tracking** - Live scan progress with detailed logging
- **System Information** - OS, Python version, architecture details

### TUI Tabs

1. **📊 Dashboard** - System information and framework status
2. **🎯 Targets** - Target management and validation
3. **🔍 Scanner** - Scan configuration and execution
4. **📋 Reports** - Results viewing and report generation
5. **⚙️ Settings** - Configuration management

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Q` | Quit application |
| `Ctrl+D` | Toggle dark mode |
| `F1-F5` | Switch between tabs |
| `Ctrl+R` | Refresh current view |

---

## 🔒 Security Features

### Input Validation & Sanitization

The framework implements comprehensive security measures:

```python
class SecurityValidator:
    """Comprehensive security validation"""
    
    DANGEROUS_PATTERNS = {
        'path_traversal': re.compile(r'\.\.\/|\.\.\\|\.\.[\/\\]'),
        'command_injection': re.compile(r'[;&|`$\(\)]'),
        'script_tags': re.compile(r'<script[^>]*>.*?</script>'),
        'sql_injection': re.compile(r'(\b(union|select|insert)\b|--|\'|")'),
        'xss_patterns': re.compile(r'(javascript:|data:|vbscript:)')
    }
```

### Secure Execution Environment

- **Sandboxed Operations** - Limited file system access
- **Resource Monitoring** - CPU and memory usage tracking
- **Rate Limiting** - Prevent resource exhaustion
- **Error Handling** - Graceful failure management

### Privacy & Anonymity

- **No Data Collection** - All processing is local
- **Configurable User Agents** - Avoid fingerprinting
- **Request Throttling** - Respectful scanning practices
- **Secure Logging** - Sanitized log outputs

---

## ⚙️ Configuration

### Default Configuration

The framework uses intelligent defaults while allowing customization:

```json
{
  "general": {
    "max_threads": 50,
    "timeout": 30,
    "retries": 3,
    "verbose": true,
    "output_format": "json"
  },
  "scanning": {
    "subdomain_wordlist_size": 10000,
    "port_scan_top_ports": 1000,
    "http_timeout": 10,
    "max_crawl_depth": 3
  },
  "security": {
    "validate_inputs": true,
    "sanitize_outputs": true,
    "rate_limiting": true,
    "max_payload_size": 1048576
  },
  "reporting": {
    "generate_html": true,
    "generate_json": true,
    "generate_csv": true,
    "include_screenshots": false
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PANTHEON_CONFIG` | Config file path | `config.json` |
| `PANTHEON_LOG_LEVEL` | Logging level | `INFO` |
| `PANTHEON_MAX_THREADS` | Max thread count | `50` |
| `PANTHEON_TIMEOUT` | Request timeout | `30` |

---

## 📚 Examples

### Example 1: Basic Reconnaissance

```bash
# Add target and run reconnaissance
python3 bl4ckc3ll_pantheon_master.py
# Select [1] Target Management → Add target: example.com
# Select [2] BCAR Reconnaissance → Run complete discovery
```

### Example 2: Quick TUI Scan

```bash
# Launch TUI and perform scan
python3 bl4ckc3ll_pantheon_master.py --tui
# Navigate to Targets tab → Add target → Scanner tab → Start scan
```

### Example 3: Automated Testing Chain

```bash
# Run complete automated assessment
python3 bl4ckc3ll_pantheon_master.py --target example.com --verbose
# Or use menu: [10] Automated Testing Chain
```

### Example 4: Security Validation

```bash
# Test input validation and sanitization
python3 bl4ckc3ll_pantheon_master.py
# Select [6] Security Validation → See demonstration
```

### Example 5: Diagnostics

```bash
# Check system status and capabilities
python3 bl4ckc3ll_pantheon_master.py
# Select [15] Tool Diagnostics → View system information
```

---

## 📋 Requirements

### System Requirements
- **OS**: Linux, macOS, Windows
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 1GB free space
- **Network**: Internet connection for external services

### Python Libraries

**Essential (Auto-installed):**
- `psutil` - System monitoring
- `requests` - HTTP operations
- `textual` - Advanced TUI

**Optional (Enhanced Features):**
- `numpy, pandas, scikit-learn` - AI/ML capabilities
- `matplotlib, plotly` - Visualization
- `cryptography` - Security features
- `boto3, azure-storage-blob, google-cloud-storage` - Cloud integration

### External Tools (Optional)

The framework gracefully handles missing external tools:
- `nmap` - Network scanning
- `subfinder` - Subdomain discovery
- `nuclei` - Vulnerability scanning
- `httpx` - HTTP probing
- `amass` - Asset discovery

---

## 🔗 Integration & Extensibility

### Plugin System

The framework supports custom plugins and extensions:

```python
# Custom plugin example
class CustomPlugin:
    def __init__(self, logger):
        self.logger = logger
    
    def execute(self, targets):
        # Custom functionality
        pass
```

### API Integration

Built-in support for:
- **Certificate Transparency APIs** - crt.sh, Certspotter
- **Cloud Provider APIs** - AWS, Azure, GCP
- **Threat Intelligence APIs** - Configurable endpoints
- **Custom Webhooks** - Result notifications

### CI/CD Integration

The framework can be integrated into CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    python3 bl4ckc3ll_pantheon_master.py --target ${{ inputs.target }} --quiet
```

---

## 🆘 Troubleshooting

### Common Issues

**Issue: Permission Denied**
```bash
chmod +x bl4ckc3ll_pantheon_master.py
```

**Issue: Missing Dependencies**
```bash
pip install -r requirements.txt --user
```

**Issue: TUI Not Working**
```bash
pip install textual>=0.70.0
```

**Issue: Network Timeouts**
- Check firewall settings
- Increase timeout values
- Use `--verbose` for debugging

### Debug Mode

```bash
# Enable verbose logging
python3 bl4ckc3ll_pantheon_master.py --verbose

# Check diagnostics
python3 bl4ckc3ll_pantheon_master.py
# Select [15] Tool Diagnostics
```

---

## 🤝 Contributing

We welcome contributions to improve the framework:

1. **Fork the repository**
2. **Create feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit changes** (`git commit -m 'Add amazing feature'`)
4. **Push to branch** (`git push origin feature/amazing-feature`)
5. **Open Pull Request**

### Development Guidelines

- Follow PEP 8 style guidelines
- Add comprehensive docstrings
- Include unit tests
- Update documentation
- Maintain backward compatibility

---

## 📜 License & Disclaimer

### License
This project is licensed for **Educational and Research Purposes Only**.

### Important Disclaimer

⚠️ **EDUCATIONAL USE ONLY** ⚠️

This tool is intended for:
- ✅ Educational purposes and learning
- ✅ Authorized security assessments
- ✅ Research and development
- ✅ Bug bounty programs (with proper scope)
- ✅ Internal red team exercises

**NOT intended for:**
- ❌ Unauthorized scanning or testing
- ❌ Malicious activities
- ❌ Illegal penetration testing
- ❌ Violation of terms of service

### Responsible Use

Users are **solely responsible** for:
- Ensuring proper authorization before testing
- Complying with local laws and regulations
- Respecting target systems and networks
- Following responsible disclosure practices

### Legal Notice

The authors and contributors:
- Provide this tool "as is" without warranty
- Are not responsible for misuse or illegal activities
- Encourage responsible and ethical security testing
- Support the security research community

---

## 🏆 Acknowledgments

Special thanks to the security research community and the following projects:
- ProjectDiscovery for excellent security tools
- The OWASP Foundation for security standards
- Certificate Transparency project contributors
- Python community for amazing libraries

---

## 📞 Support & Contact

- **Documentation**: [Wiki Pages](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON/wiki)
- **Issues**: [GitHub Issues](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON/discussions)
- **Author**: [@cxb3rf1lth](https://github.com/cxb3rf1lth)

---

**Bl4ckC3ll PANTHEON MASTER** - *The Ultimate Consolidated Security Testing Framework*  
*Version 10.0.0-MASTER-CONSOLIDATED* | *Educational Use Only* | *Test Responsibly* 🔒

---

*Made with ❤️ for the security research community*