# Bl4ckC3ll_PANTHEON


Advanced offensive security orchestrator for authorized assessments. It automates discovery and triage across reconnaissance, endpoint harvesting, vulnerability scanning, and professional reporting, with strong defaults, resource awareness, and a plugin system for team-specific extensions.

This project is designed for lab, internal red team, and authorized bug bounty use only.

## Highlights

- Menu driven UX with safe defaults and granular settings
- Reconnaissance
  - Subdomain discovery with subfinder and amass
  - Port discovery with naabu
  - HTTP fingerprinting with httpx
  - Endpoint harvesting with gau and katana
- Vulnerability scanning
  - Nuclei on curated URL scopes
  - False positive reduction pipeline with light HTTP revalidation
- Reporting
  - HTML, JSON, and CSV
  - Per target sections with validated findings
  - Automatic Interesting Endpoints list for human follow up
- Operations
  - Resource monitor to avoid overloading hosts
  - Parallel execution with configurable concurrency
  - Plugin system for custom stages
  - Resilient command execution with retries and timeouts

## Requirements

- OS: Linux or macOS
- Python: 3.9 or newer
- Go: 1.20 or newer for ProjectDiscovery and tomnomnom tools
- Recommended external tools on PATH:
  - subfinder, amass, naabu, httpx, nuclei
  - gau, katana

The orchestrator detects tools at runtime. Missing tools are skipped gracefully. Reporting and the rest of the pipeline continue to work with whatever is available.

## Quick start

```bash
# 1) Clone the repo
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON

# 2) Run the automated setup (recommended)
./quickstart.sh
```

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

On first runs, select:
- Refresh Sources + Merge Wordlists
- Reconnaissance
- Vulnerability Scan
- Generate Report

## Menu overview

The main menu provides:

1. Manage Targets
2. Refresh Sources + Merge Wordlists
3. Reconnaissance
4. Vulnerability Scan
5. Full Pipeline
6. Generate Report for Latest Run
7. Settings
8. Plugins
9. View Last Report
10. Exit

Settings let you toggle nuclei, severity filters, endpoint harvesters, URL caps, concurrency, and HTTP revalidation timeout.

## Pipeline details

### Reconnaissance

- Subdomains: subfinder and amass run independently then merged
- Ports: naabu scans target host for TCP ports
- HTTP: httpx fingerprints hosts and captures titles, status codes, technologies, TLS, and content hints
- Endpoints: optional historical and crawl based URL harvesting with gau and katana, deduplicated and capped per target

Outputs are normalized into per target folders under runs/<run-id>/recon.

### Vulnerability scanning

- URL scope
  - Uses httpx records and harvested endpoints
  - Falls back to scheme and host if discovery is limited
- Nuclei
  - Severity filter by configuration
  - Rate limit and worker concurrency tunable
  - Optional templates directory set to ~/nuclei-templates if present

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
