# Bl4ckC3ll_PANTHEON

## Enhanced Advanced Security Testing Framework

Advanced offensive security orchestrator for authorized assessments with **AI-powered analysis**, **cloud security testing**, **BCAR reconnaissance**, and **CI/CD integration**. It automates discovery and triage across reconnaissance, endpoint harvesting, vulnerability scanning, and professional reporting, with strong defaults, resource awareness, and an extensible plugin system.

This project is designed for lab, internal red team, and authorized bug bounty use only.

## Enhanced Highlights

### Advanced Reconnaissance & BCAR
- **BCAR Enhanced Reconnaissance** with certificate transparency and multi-source discovery
- **Multi-source subdomain discovery** with subfinder, amass, and certificate transparency
- **Advanced Subdomain Takeover Detection** with 13+ cloud service signatures
- **Enhanced port discovery** with naabu and masscan
- **Comprehensive HTTP fingerprinting** with httpx and technology detection
- **Advanced endpoint harvesting** with gau, katana, waybackurls, and gospider
- **OSINT integration** with passive intelligence gathering

### Advanced Security Testing
- **Automated Payload Injection** with multi-platform payload generation
- **Comprehensive Advanced Fuzzing** with 500+ directory and parameter patterns
- **Meterpreter Integration** with MSFvenom command generation and listener setup
- **Safety Mode** with test mode for secure payload development

### Next-Generation Vulnerability Scanning
- **Nuclei** with enhanced template management and custom rules
- **API security testing** including REST, GraphQL, and SOAP
- **JWT token analysis** and authentication bypass testing
- **Cloud storage bucket discovery** (AWS S3, Azure Blob, GCP)
- **Container security** and Kubernetes exposure detection
- **OWASP Top 10** and compliance-specific checks
- **Machine Learning false positive reduction**

### Cloud Security Assessment
- **Multi-cloud support**: AWS, Azure, Google Cloud Platform
- **Storage bucket enumeration** and misconfiguration detection
- **Container registry scanning** (Docker Hub, ECR, ACR, GCR)
- **Kubernetes API** and dashboard exposure testing
- **Cloud metadata service** SSRF testing
- **Infrastructure as Code** security analysis

### AI-Powered Analysis
- **Intelligent vulnerability prioritization** using ML algorithms
- **False positive reduction** with confidence scoring
- **Risk scoring** based on multiple threat factors
- **Pattern recognition** for vulnerability clusters
- **Automated threat correlation** and impact assessment

### Professional Reporting
- **Multiple formats**: HTML, JSON, CSV, SARIF, JUnit
- **Interactive dashboards** with risk visualization
- **Executive summaries** with business impact analysis
- **Compliance reporting** (OWASP, NIST, PCI-DSS, GDPR)
- **Trend analysis** and historical comparisons
- **Integration-ready** outputs for security tools

### CI/CD Integration
- **GitHub Actions** workflows included
- **Docker containerization** for scalable deployment  
- **API endpoints** for programmatic access
- **Webhook notifications** and automated reporting
- **Fail-fast** configuration with customizable thresholds
- **SARIF output** for security dashboard integration

### Enhanced Plugin System
- **Advanced OSINT** collection and correlation
- **API security scanner** with comprehensive testing
- **Cloud security assessment** across multiple providers
- **Custom compliance** modules and frameworks
- **Threat intelligence** integration and enrichment

## Enhanced Requirements

### Core Requirements
- **OS**: Linux or macOS (Ubuntu 20.04+ recommended)
- **Python**: 3.9 or newer (3.11+ recommended for ML features)
- **Go**: 1.20 or newer for ProjectDiscovery and community tools
- **Memory**: 4GB+ RAM (8GB+ recommended for full scans)
- **Storage**: 10GB+ free space for templates and results

### Security Tools (Auto-installed via install.sh)
#### Core Tools
- `subfinder`, `amass` - Subdomain discovery
- `naabu`, `masscan` - Port scanning  
- `httpx` - HTTP probing and fingerprinting
- `nuclei` - Vulnerability scanning with templates
- `katana`, `gau`, `waybackurls`, `gospider` - Endpoint discovery

#### Enhanced Tools
- `gobuster`, `dirb`, `ffuf` - Directory and file fuzzing
- `nikto`, `sqlmap`, `whatweb` - Web application security
- `subjack`, `subzy` - Subdomain takeover detection
- `wappalyzer` - Technology detection
- `paramspider`, `arjun` - Parameter discovery
- `dalfox` - XSS detection

#### BCAR Dependencies
- Certificate transparency APIs (crt.sh, certspotter)
- Multi-threading support for concurrent scanning
- Advanced payload libraries (MSFvenom, Metasploit)

#### System Tools
- `curl`, `wget`, `openssl`, `dig`, `whois`, `nmap`

### Python Dependencies (Enhanced)
```bash
# Core system monitoring
psutil>=5.9.0
distro>=1.8.0
requests>=2.28.0

# Machine Learning and Analysis  
scikit-learn>=1.1.0
numpy>=1.21.0
pandas>=1.5.0

# Web Security and API Testing
beautifulsoup4>=4.11.0
pycryptodome>=3.15.0

# Report Generation and Visualization
matplotlib>=3.6.0
plotly>=5.11.0
jinja2>=3.1.0

# Cloud Security
boto3>=1.26.0
azure-storage-blob>=12.14.0
google-cloud-storage>=2.7.0

# Network Analysis
python-nmap>=0.7.1
netaddr>=0.8.0
```

The orchestrator detects tools at runtime. Missing tools are skipped gracefully with fallback mechanisms.

## Enhanced Quick Start

### Automated Setup (Recommended)
```bash
# 1) Clone the enhanced repository
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON

# 2) Run automated setup with enhanced tools
./quickstart.sh

# 3) Start the enhanced framework
python3 bl4ckc3ll_p4nth30n.py
```

### Docker Deployment (New!)
```bash
# Build the container with all tools
docker build -t bl4ckc3ll-pantheon .

# Run interactive mode
docker run -it -v $(pwd)/results:/app/results bl4ckc3ll-pantheon

# Run automated scan
docker run -v $(pwd)/results:/app/results bl4ckc3ll-pantheon \
  python3 cicd_integration.py --target example.com --scan-type full
```

### CI/CD Integration (New!)
```bash
# Quick security scan for CI/CD
python3 cicd_integration.py \
  --target your-target.com \
  --scan-type quick \
  --output-format sarif \
  --fail-on high

# Full assessment with all features
python3 cicd_integration.py \
  --target your-target.com \
  --scan-type full \
  --output-format json \
  --fail-on medium \
  --timeout 3600
```

## Enhanced Menu Overview

The enhanced main menu provides:

### Core Functions (Enhanced)
1. **Manage Targets** - Multi-target configuration
2. **Refresh Sources + Merge Wordlists** - Enhanced wordlist management  
3. **Enhanced Reconnaissance** - Multi-source intelligence gathering
4. **Advanced Vulnerability Scan** - 13-phase comprehensive testing
5. **Full Pipeline** - Complete automated assessment
6. **Generate Enhanced Report** - Multi-format professional reports

### Advanced Features
7. **Settings & Configuration** - Granular control and optimization
8. **Plugins Management** - Extensible functionality system
9. **View Last Report** - Interactive report viewing
10. **Network Analysis Tools** - Deep network reconnaissance
11. **Security Assessment Summary** - Executive dashboard

### Next-Generation Capabilities
12. **AI-Powered Vulnerability Analysis** - Machine learning insights
13. **Cloud Security Assessment** - Multi-cloud security testing  
14. **API Security Testing** - Comprehensive API vulnerability scanning
15. **Compliance & Risk Assessment** - Regulatory compliance testing
16. **CI/CD Integration Mode** - Automated pipeline integration

### BCAR Enhanced Capabilities (NEW!)
24. **BCAR Enhanced Reconnaissance** - Certificate transparency and advanced discovery
25. **Advanced Subdomain Takeover** - Cloud service takeover detection and validation
26. **Automated Payload Injection** - Multi-platform payload generation with safety mode
27. **Comprehensive Advanced Fuzzing** - 500+ directory and parameter pattern testing
28. **Exit** - Clean application termination

## Enhanced Pipeline Details

### Phase 1: Advanced Reconnaissance & BCAR
- **BCAR Enhanced Reconnaissance** with certificate transparency integration
- **Multi-source subdomain discovery** (subfinder, amass, certificate transparency)
- **Advanced Subdomain Takeover Detection** with 13+ cloud service signatures
- **Enhanced port scanning** (naabu, masscan with intelligent rate limiting)  
- **Comprehensive HTTP analysis** (httpx with technology detection)
- **Advanced endpoint harvesting** (gau, katana, waybackurls, gospider)
- **DNS enumeration** with historical analysis
- **SSL/TLS analysis** with certificate transparency logs
- **Network analysis** with ASN and geolocation mapping

### Phase 2: Next-Gen Vulnerability Scanning & Exploitation
- **Automated Payload Injection** with multi-platform payload generation
- **Comprehensive Advanced Fuzzing** with 500+ directory and parameter patterns
- **Nuclei** with enhanced templates and custom rules
- **Security headers** analysis with compliance mapping
- **CORS** misconfiguration detection
- **API endpoint discovery** and security testing
- **GraphQL** introspection and query analysis  
- **JWT token** security and algorithm testing
- **Cloud storage** bucket enumeration and testing
- **Threat intelligence** correlation and enrichment
- **Compliance checks** (OWASP, PCI-DSS, NIST)
- **Container** and Kubernetes security assessment
- **Machine Learning** false positive reduction

### Phase 3: Advanced Analysis & Reporting
- **Risk scoring** with ML-based prioritization
- **Vulnerability correlation** and impact analysis  
- **Executive summary** generation
- **Multi-format exports** (HTML, JSON, CSV, SARIF, JUnit)
- **Interactive dashboards** with drill-down capability
- **Compliance mapping** to regulatory frameworks
- **Trend analysis** and historical comparisons

### BCAR-Specific Capabilities
- **Certificate Transparency Search** via crt.sh and certspotter APIs
- **Multi-threaded DNS Resolution** for subdomain validation
- **Meterpreter Integration** with MSFvenom command generation
- **Listener Setup Scripts** for automated exploitation setup
- **Safety Mode Configuration** for secure testing environments

The quickstart script will automatically:
- Validate Python 3.9+ installation
- Install Python dependencies
- Install Go and security tools
- Setup environment variables
- Create necessary directories
- Run installation tests
- Start the application

### Manual installation (alternative)

```bash
# 1) Validate Python version
python3 -V  # ensure 3.9+

# 2) Run automated installer
./install.sh

# 3) Test installation
python3 test_installation.py

# 4) Add targets (one per line)
echo "example.com" > targets.txt

# 5) Run the orchestrator
python3 bl4ckc3ll_p4nth30n.py
```

### Individual tool installation (if needed)

```bash
# Install Python dependencies manually
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Install Go-based tools
export PATH="$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:$PATH"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

## BCAR Enhanced Usage

### Quick BCAR Setup
```bash
# 1) Run BCAR-specific setup
./setup_bcar.sh

# 2) Configure targets
echo "target-domain.com" > targets.txt

# 3) Launch framework
python3 bl4ckc3ll_p4nth30n.py

# 4) Select BCAR options from menu:
#    24. [BCAR] BCAR Enhanced Reconnaissance
#    25. [TAKEOVER] Advanced Subdomain Takeover  
#    26. [PAYINJECT] Automated Payload Injection
#    27. [FUZZ] Comprehensive Advanced Fuzzing
```

### BCAR Configuration
```json
{
  "bcar": {
    "ct_search": true,
    "subdomain_enum": true, 
    "takeover_check": true,
    "port_scan": true,
    "tech_detection": true,
    "directory_fuzz": true,
    "parameter_discovery": true
  },
  "payload_injection": {
    "lhost": "127.0.0.1",
    "lport": 4444,
    "test_mode": true
  }
}
```

### BCAR Standalone Usage
```bash
# Run BCAR module independently
python3 bcar.py target.com --output results.json --verbose

# Certificate transparency only
python3 bcar.py target.com --ct-only

# Subdomain takeover check only
python3 bcar.py target.com --takeover-only
```

### Comprehensive Documentation
For detailed BCAR usage, configuration options, and best practices:
```bash
# View complete BCAR usage guide
cat BCAR_USAGE_GUIDE.md

# Run BCAR setup and validation
./setup_bcar.sh
```

On first runs, select:
- Refresh Sources + Merge Wordlists
- BCAR Enhanced Reconnaissance (option 24)
- Advanced Subdomain Takeover (option 25)
- Comprehensive Advanced Fuzzing (option 27)
- Generate Enhanced Report

## Menu Overview

The main menu provides:

### Core Operations (1-10)
1. Enhanced Target Management
2. Refresh Sources + Merge Wordlists
3. Enhanced Reconnaissance
4. Advanced Vulnerability Scan
5. Full Pipeline (Recon + Vuln + Report)
6. Quick Preset Scan Configurations
7. Generate Enhanced Report
8. Settings & Configuration
9. Plugins Management
10. View Last Report

### Advanced Features (11-23)
11. Network Analysis Tools
12. Security Assessment Summary
13. AI-Powered Vulnerability Analysis
14. Cloud Security Assessment
15. API Security Testing
16. Compliance & Risk Assessment
17. CI/CD Integration Mode
18. ESLint Security Check
19. Bug Bounty Automation
20. Automated Testing Chain
21. Launch Advanced TUI Interface
22. Enhanced Payload Management
23. Tool Status & Fallback Management

### BCAR Enhanced Capabilities (24-28)
24. **[BCAR]** BCAR Enhanced Reconnaissance
25. **[TAKEOVER]** Advanced Subdomain Takeover
26. **[PAYINJECT]** Automated Payload Injection
27. **[FUZZ]** Comprehensive Advanced Fuzzing
28. **[EXIT]** Exit

Settings allow configuration of nuclei templates, severity filters, endpoint harvesters, URL caps, concurrency, HTTP timeout, and BCAR-specific options.

## Pipeline Details

### Enhanced Reconnaissance & BCAR

- **BCAR Enhanced Reconnaissance**: Certificate transparency search, advanced subdomain enumeration, technology detection
- **Subdomains**: subfinder, amass, and certificate transparency logs run independently then merged
- **Subdomain Takeover**: Automated detection for 13+ cloud services (GitHub Pages, Heroku, AWS S3, etc.)
- **Ports**: naabu scans target host for TCP ports with intelligent rate limiting
- **HTTP**: httpx fingerprints hosts and captures titles, status codes, technologies, TLS, and content hints
- **Endpoints**: Historical and crawl-based URL harvesting with gau, katana, waybackurls, gospider
- **Advanced Fuzzing**: 500+ directory and parameter patterns with multi-threaded execution

Outputs are normalized into per-target folders under runs/<run-id>/ with BCAR-specific results in JSON format.

### Advanced Vulnerability Scanning

- **Automated Payload Injection**: Multi-platform payload generation (Bash, Python, PHP, PowerShell, Perl, Ruby)
- **Meterpreter Integration**: MSFvenom command generation and listener setup scripts
- **URL scope**: Uses httpx records and harvested endpoints, falls back to scheme and host if discovery is limited
- **Nuclei**: Severity filtering by configuration, rate limiting and worker concurrency tunable
- **Safety Mode**: Test mode prevents accidental execution of payloads
- **Parameter Discovery**: Advanced parameter fuzzing with 400+ common parameter names

### False positive reduction

Nuclei JSONL output is processed with:

- Deduplication by templateID, host, and matched-at
- Configurable removal of info severity
- Lightweight revalidation
  - HTTP fetch of matched-at
  - Accepts codes 200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500
  - Marks unexpected statuses as filtered out with a reason

Validated findings are carried into the report. Filtered items are still listed to aid triage.

### Interesting endpoints

The report highlights a short list of URLs matching patterns worth human review, including:

- Authentication and administrative paths
- Environment artifacts and historical backups
- GraphQL, versioned APIs, and parameterized endpoints

Patterns are configurable in code and can be extended.

## Reports

Generated under runs/<run-id>/report

- report.html
  - Executive summary cards
  - Reconnaissance with subdomains, ports, and HTTP samples
  - Validated findings table per target
  - Filtered out candidates with reasons
  - Interesting endpoints
- report.json
  - Full structured data for programmatic consumption
- report_validated.csv
  - Flattened validated findings across all targets

The HTML report uses a neutral dark theme without ANSI artifacts. It can auto open on completion if enabled.

## Configuration

Configuration is stored in p4nth30n.cfg.json and created on first run. Important keys:

```json
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
    "auto_open_html": true,
    "include_viz": true
  }
}
```

Edit the file or use the Settings menu to tweak values.

## Directory structure

```
.
├─ bl4ckc3ll_p4nth30n.py
├─ targets.txt
├─ runs/
│  └─ <run-id>/
│     ├─ recon/
│     ├─ vuln_scan/
│     └─ report/
├─ logs/
│  └─ bl4ckc3ll_p4nth30n.log
├─ external_lists/
├─ lists_merged/
├─ plugins/
└─ p4nth30n.cfg.json
```

## Plugins

Plugins are simple Python modules loaded from plugins. Each plugin exports:

```python
plugin_info = {"name": "example", "description": "...", "version": "1.0.0", "author": "you"}
def execute(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    ...
```

Use the Plugins menu to scaffold a new plugin file and execute plugins on a given run.

## Performance and resource awareness

A background resource monitor periodically checks CPU, memory, and disk utilization. If thresholds are exceeded, execution throttles. You can tune thresholds and intervals in the configuration.

Concurrency defaults are conservative. Increase max_concurrent_scans gradually on large hosts. Consider rate limits for naabu and nuclei according to your environment and authorization.

## Troubleshooting

- Tools not found
  - Ensure PATH includes $HOME/go/bin and your package manager binary path
  - Confirm go install placed binaries under $HOME/go/bin
- Nuclei templates are not loading
  - By default the tool uses ~/nuclei-templates if present
  - Update the templates path or run nuclei with -update-templates externally
- Very few endpoints discovered
  - Enable gau and katana in Settings
  - Increase max_urls_per_target and katana depth carefully
- Reports missing sections
  - If a tool was not found or returned no output, the section is still generated with empty lists

## CI example

You can run light checks in CI to validate the repository builds and produce a minimal dry run.

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  lint-and-dry-run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install minimal deps
        run: |
          python -m pip install --upgrade pip
          echo "example.com" > targets.txt
      - name: Dry run
        run: |
          python bl4ckc3ll_p4nth30n.py <<EOF
          6
          EOF
      - name: Archive latest report
        if: always()
        run: |
          LATEST=$(ls -1t runs | head -n1)
          tar -czf report-artifacts.tgz runs/$LATEST/report || true
      - uses: actions/upload-artifact@v4
        with:
          name: report-artifacts
          path: report-artifacts.tgz
```

This example runs a minimal report generation in CI to validate the workflow. External tools are optional.

## Security and legal

Only scan assets you are explicitly authorized to test. Running active discovery and vulnerability scanning on systems you do not own or control may be illegal. The maintainers and contributors assume no liability for misuse.

## Roadmap

- Optional authenticated scanning helpers
- Multi run comparison reports
- Exporters for SARIF and JUnit
- Target tagging and per tag settings
- Pluggable false positive validators per template family

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request. Keep PRs focused and small. Include test plans and sample outputs where appropriate.

```text
Coding style
- Keep subprocess calls argument based when possible
- Add timeouts to external calls
- Log at INFO for major stage transitions and at DEBUG for command outputs
- Prefer deterministic filenames under runs/<run-id> to simplify parsing
```

## Acknowledgments

This project builds on excellent open source tools, including the ProjectDiscovery suite, tomnomnom utilities, and many others in the security community.
