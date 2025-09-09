# 🛡️ Bl4ckC3ll PANTHEON - Advanced Security Testing Framework

## 🎯 World-Class Professional TUI Application

**Bl4ckC3ll PANTHEON** is now a **complete, production-ready security testing framework** with a world-class Terminal User Interface (TUI) that provides comprehensive penetration testing and vulnerability assessment capabilities in a single, integrated application.

---

## ✨ **NEW: Consolidated Master TUI Application**

### 🚀 **Quick Start - One Command Installation**

```bash
# Clone and install everything
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON
./install_consolidated.sh

# Launch the advanced TUI
./bl4ckc3ll_pantheon
```

---

## 🎯 **Core Features**

### 🖥️ **Professional TUI Interface**
- **Real-time system monitoring** with CPU, memory, and disk usage
- **Interactive target management** with validation and bulk import
- **Live scan execution** with progress bars and real-time logs
- **Professional report viewing** and export capabilities
- **Keyboard shortcuts** and intuitive navigation
- **Responsive design** that adapts to terminal size

### 🔍 **Advanced Security Testing**
- **Multi-source reconnaissance** (subfinder, amass, certificate transparency)
- **Comprehensive port scanning** (naabu, masscan, nmap)
- **Web application testing** with advanced crawling and analysis
- **Vulnerability scanning** with Nuclei and custom templates
- **API security testing** for REST, GraphQL, and SOAP
- **Cloud security assessment** (AWS, Azure, GCP)
- **Subdomain takeover detection**
- **Advanced payload injection testing**

### 📊 **Intelligence & Reporting**
- **Multi-format reports** (HTML, JSON, CSV, SARIF)
- **Executive summaries** with risk prioritization
- **Interactive dashboards** with drill-down capabilities
- **Compliance mapping** (OWASP, PCI-DSS, NIST)
- **Trend analysis** and historical comparisons
- **Professional styling** for client presentations

### 🔧 **Enterprise Features**
- **Target validation** and sanitization
- **Resource monitoring** and throttling
- **Configuration management** with profiles
- **Plugin architecture** for extensibility
- **Backend integration** with CLI tools
- **Error handling** and graceful degradation

---

## 🖼️ **Interface Preview**

```
┌─ Bl4ckC3ll PANTHEON - Advanced Security Testing Framework ─┐
│ 📊 Dashboard  🎯 Targets  🔍 Scanner  📋 Reports          │
├───────────────────────────────────────────────────────────┤
│ ┌─ System Dashboard ─────┐  ┌─ Resource Monitor ──────────┐│
│ │ OS: Linux 6.11.0       │  │ CPU:  ████░░░░░░░░ 35%     ││
│ │ Python: 3.12.3         │  │ RAM:  ██░░░░░░░░░░ 18%     ││
│ │ ✅ TUI Active          │  │ Disk: ████████░░░ 64%     ││
│ │ 🔧 Backend: Available  │  └─────────────────────────────┘│
│ └────────────────────────┘                                │
│ ┌─ Target Management ──────────────────────────────────────┐│
│ │ Add Target: [example.com        ] [Add]                 ││
│ │ ┌─ Current Targets ────────────────────────────────────┐ ││
│ │ │ Target          │ Status │ Type   │ Last Scan       │ ││
│ │ │ example.com     │ Ready  │ Domain │ Not Scanned     │ ││
│ │ └───────────────────────────────────────────────────────┘ ││
│ └─────────────────────────────────────────────────────────┘│
└───────────────────────────────────────────────────────────┘
```

---

## 🚀 **Installation Methods**

### **Method 1: Automated Installation (Recommended)**
```bash
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON
./install_consolidated.sh
```

### **Method 2: Manual Installation**
```bash
# Install Python dependencies
pip3 install textual psutil requests beautifulsoup4 lxml numpy pandas

# Install Go-based security tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Clone repository
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON
```

### **Method 3: Docker Deployment**
```bash
# Build container with all tools
docker build -t bl4ckc3ll-pantheon .

# Run interactive TUI mode
docker run -it -v $(pwd)/results:/app/results bl4ckc3ll-pantheon

# Run CLI mode
docker run -v $(pwd)/results:/app/results bl4ckc3ll-pantheon \
  python3 bl4ckc3ll_p4nth30n.py
```

---

## 🎮 **Usage Guide**

### **TUI Mode (Recommended)**
```bash
# Launch the advanced TUI interface
./bl4ckc3ll_pantheon

# Or directly with Python
python3 tui_consolidated.py
```

### **CLI Mode (Advanced Users)**
```bash
# Traditional CLI interface
./bl4ckc3ll_pantheon_cli

# Or directly with Python  
python3 bl4ckc3ll_p4nth30n.py
```

### **Keyboard Shortcuts**
- **F1**: Dashboard - System monitoring and status
- **F2**: Targets - Target management and configuration
- **F3**: Scanner - Scan configuration and execution
- **F4**: Reports - Report viewing and export
- **Ctrl+Q**: Quit application
- **Ctrl+R**: Refresh current view

---

## 📋 **Scan Types Available**

| Scan Type | Description | Duration | Tools Used |
|-----------|-------------|----------|------------|
| **Quick Reconnaissance** | Fast subdomain and port discovery | 5-15 min | subfinder, naabu, httpx |
| **Full Security Scan** | Complete assessment pipeline | 30-120 min | All tools + nuclei |
| **Vulnerability Scan Only** | Focused vulnerability testing | 15-45 min | nuclei, custom templates |
| **Subdomain Discovery** | Advanced subdomain enumeration | 10-30 min | subfinder, amass, CT logs |
| **Port Scanning** | Comprehensive port analysis | 5-20 min | naabu, masscan, nmap |
| **Web Application Test** | Web app security assessment | 20-60 min | katana, gau, nuclei |
| **API Security Test** | REST/GraphQL/SOAP testing | 15-45 min | nuclei API templates |
| **Cloud Security Assessment** | Multi-cloud security testing | 10-30 min | Cloud-specific tools |

---

## 📊 **Configuration Options**

### **p4nth30n.cfg.json**
```json
{
  "limits": {
    "parallel_jobs": 20,
    "http_timeout": 15,
    "rps": 500,
    "max_concurrent_scans": 8
  },
  "nuclei": {
    "enabled": true,
    "severity": "low,medium,high,critical",
    "rps": 800,
    "conc": 150
  },
  "endpoints": {
    "use_gau": true,
    "use_katana": true,
    "max_urls_per_target": 5000
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
```

---

## 🔧 **Advanced Features**

### **Target Management**
- **Input validation** with domain/IP format checking
- **Bulk import** from text files or clipboard
- **Target categorization** by type and priority
- **Status tracking** and scan history
- **Export/import** functionality

### **Real-time Monitoring**
- **System resource usage** (CPU, memory, disk)
- **Scan progress** with detailed phase information
- **Live output logs** with filtering and search
- **Performance metrics** and optimization suggestions

### **Report Generation**
- **Multiple output formats** for different audiences
- **Executive summaries** with risk scoring
- **Technical details** with proof-of-concepts
- **Compliance mapping** to security frameworks
- **Custom templates** and branding options

### **Integration Capabilities**
- **CI/CD pipeline** integration
- **API endpoints** for programmatic access
- **Webhook notifications** for real-time alerts
- **SIEM integration** with structured outputs
- **Custom plugin** development framework

---

## 🛡️ **Security & Legal**

### **Authorization Required**
⚠️ **IMPORTANT**: Only use this tool on systems you own or have explicit written authorization to test. Unauthorized scanning is illegal and unethical.

### **Responsible Disclosure**
- Follow responsible disclosure practices
- Report vulnerabilities to appropriate parties
- Respect rate limits and system resources
- Document all testing activities

### **Legal Compliance**
- Ensure compliance with local laws and regulations
- Obtain proper authorization before testing
- Maintain audit trails and documentation
- Respect privacy and data protection laws

---

## 🚀 **Performance & Scaling**

### **System Requirements**
- **OS**: Linux, macOS, or WSL2 on Windows
- **Python**: 3.9+ (3.11+ recommended)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 10GB free space for reports and templates
- **Network**: Unrestricted internet access for tools

### **Optimization Tips**
- Adjust `parallel_jobs` based on system capabilities
- Use `rps` limits to avoid rate limiting
- Configure `max_concurrent_scans` for memory management
- Enable `auto_refresh` for real-time monitoring

---

## 🔄 **CI/CD Integration**

### **GitHub Actions Example**
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Bl4ckC3ll PANTHEON
        run: |
          ./install_consolidated.sh
          echo "target.example.com" > targets.txt
          python3 tui_consolidated.py --automated --output sarif
```

---

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:
- Code style and standards
- Testing requirements
- Pull request process
- Issue reporting
- Feature requests

---

## 📞 **Support & Community**

- **Issues**: [GitHub Issues](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON/discussions)
- **Security**: Report security issues privately via email
- **Documentation**: [Wiki](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON/wiki)

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

Built with excellent open-source tools from:
- **ProjectDiscovery** (nuclei, subfinder, httpx, naabu, katana)
- **Textual** (modern TUI framework)
- **Security Community** (templates, wordlists, techniques)

---

<div align="center">
<h3>🛡️ Professional Security Testing Made Simple 🛡️</h3>
<p><em>Bl4ckC3ll PANTHEON - Where Security Meets Excellence</em></p>
</div>