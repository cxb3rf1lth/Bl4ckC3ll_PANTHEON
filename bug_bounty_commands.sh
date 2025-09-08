#!/bin/bash
# Bug Bounty Automation Commands for Bl4ckC3ll_PANTHEON
# Author: @cxb3rf1lth
# Description: Comprehensive bug bounty reconnaissance and testing automation

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/bug_bounty_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${RESULTS_DIR}/bug_bounty_${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p "${RESULTS_DIR}"

# Logging function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

# Error handling
error_exit() {
    log "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

# Success logging
success() {
    log "${GREEN}[SUCCESS] $1${NC}"
}

# Warning logging
warning() {
    log "${YELLOW}[WARNING] $1${NC}"
}

# Info logging
info() {
    log "${BLUE}[INFO] $1${NC}"
}

# Check if tools are installed
check_tools() {
    local missing_tools=()
    
    # Core bug bounty tools
    local tools=(
        "subfinder" "httpx" "naabu" "nuclei" "katana" "gau"
        "amass" "masscan" "nmap" "sqlmap" "ffuf" "gobuster"
        "waybackurls" "subjack" "subzy" "whatweb" "nikto"
        "paramspider" "dalfox" "arjun" "feroxbuster"
    )
    
    for tool in "${tools[@]}"; do
        if ! command -v "${tool}" &> /dev/null; then
            missing_tools+=("${tool}")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        warning "Missing tools: ${missing_tools[*]}"
        info "Run install.sh to install missing tools"
    else
        success "All bug bounty tools are available"
    fi
}

# Subdomain enumeration
subdomain_enum() {
    local target="$1"
    local output_dir="${RESULTS_DIR}/subdomains"
    mkdir -p "${output_dir}"
    
    info "Starting subdomain enumeration for ${target}"
    
    # Subfinder - passive subdomain enumeration
    if command -v subfinder &> /dev/null; then
        info "Running subfinder..."
        subfinder -d "${target}" -o "${output_dir}/subfinder_${target}.txt" -silent
        success "Subfinder completed"
    fi
    
    # Amass - comprehensive subdomain enumeration
    if command -v amass &> /dev/null; then
        info "Running amass enum..."
        timeout 300 amass enum -d "${target}" -o "${output_dir}/amass_${target}.txt" || warning "Amass timed out"
    fi
    
    # Combine and deduplicate results
    if ls "${output_dir}"/*.txt &> /dev/null; then
        cat "${output_dir}"/*.txt | sort -u > "${output_dir}/all_subdomains_${target}.txt"
        local count=$(wc -l < "${output_dir}/all_subdomains_${target}.txt")
        success "Found ${count} unique subdomains for ${target}"
    fi
}

# Port scanning
port_scan() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/ports"
    mkdir -p "${output_dir}"
    
    info "Starting port scanning"
    
    # Naabu - fast port scanner
    if command -v naabu &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running naabu port scan..."
        naabu -list "${targets_file}" -p - -o "${output_dir}/naabu_ports.txt" -silent
        success "Naabu scan completed"
    fi
    
    # Masscan - high-speed port scanner
    if command -v masscan &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running masscan..."
        # Only scan top ports to avoid overwhelming the target
        masscan -iL "${targets_file}" -p1-1000 --rate=1000 -oG "${output_dir}/masscan_ports.txt" || warning "Masscan failed"
    fi
}

# HTTP probing
http_probe() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/http"
    mkdir -p "${output_dir}"
    
    info "Starting HTTP probing"
    
    # HTTPx - fast HTTP prober
    if command -v httpx &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running httpx probe..."
        httpx -list "${targets_file}" -o "${output_dir}/live_hosts.txt" -silent \
              -title -tech-detect -status-code -content-length
        success "HTTPx probing completed"
    fi
}

# Directory and file discovery
directory_bruteforce() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/directories"
    mkdir -p "${output_dir}"
    
    info "Starting directory bruteforce"
    
    # FFUF - fast web fuzzer
    if command -v ffuf &> /dev/null && [[ -f "${targets_file}" ]]; then
        local wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        if [[ ! -f "${wordlist}" ]]; then
            wordlist="${SCRIPT_DIR}/wordlists_extra/common_directories.txt"
        fi
        
        if [[ -f "${wordlist}" ]]; then
            info "Running ffuf directory bruteforce..."
            while IFS= read -r url; do
                [[ -z "${url}" ]] && continue
                ffuf -u "${url}/FUZZ" -w "${wordlist}" -o "${output_dir}/ffuf_$(basename "${url}").json" \
                     -of json -t 10 -mc 200,301,302,403 -fs 0 -silent || warning "FFUF failed for ${url}"
            done < <(head -10 "${targets_file}") # Limit to first 10 targets to avoid overwhelming
            success "FFUF directory bruteforce completed"
        fi
    fi
    
    # Feroxbuster - recursive directory scanner
    if command -v feroxbuster &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running feroxbuster..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            feroxbuster -u "${url}" -o "${output_dir}/ferox_$(basename "${url}").txt" \
                       -t 10 -C 404 -x php,html,js,txt,xml -q || warning "Feroxbuster failed for ${url}"
        done < <(head -5 "${targets_file}") # Limit to first 5 targets
    fi
}

# Parameter discovery
param_discovery() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/parameters"
    mkdir -p "${output_dir}"
    
    info "Starting parameter discovery"
    
    # Arjun - HTTP parameter discovery
    if command -v arjun &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running arjun parameter discovery..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            arjun -u "${url}" -o "${output_dir}/arjun_$(basename "${url}").txt" \
                  -t 10 -q || warning "Arjun failed for ${url}"
        done < <(head -5 "${targets_file}")
        success "Arjun parameter discovery completed"
    fi
    
    # ParamSpider - parameter mining from web archives
    if command -v paramspider &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running paramspider..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            paramspider -d "$(echo "${url}" | sed 's|^https\?://||' | cut -d'/' -f1)" \
                       -o "${output_dir}/paramspider_$(basename "${url}").txt" || warning "ParamSpider failed for ${url}"
        done < <(head -3 "${targets_file}")
    fi
}

# Vulnerability scanning
vuln_scan() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/vulnerabilities"
    mkdir -p "${output_dir}"
    
    info "Starting vulnerability scanning"
    
    # Nuclei - comprehensive vulnerability scanner
    if command -v nuclei &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running nuclei vulnerability scan..."
        nuclei -list "${targets_file}" -o "${output_dir}/nuclei_results.txt" \
               -severity critical,high,medium -silent -stats
        success "Nuclei vulnerability scan completed"
    fi
    
    # SQLMap - SQL injection testing
    if command -v sqlmap &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running sqlmap for SQL injection testing..."
        local params_file="${RESULTS_DIR}/parameters/all_parameters.txt"
        if [[ -f "${params_file}" ]]; then
            while IFS= read -r url; do
                [[ -z "${url}" ]] && continue
                timeout 60 sqlmap -u "${url}" --batch --random-agent --level=1 --risk=1 \
                    --output-dir="${output_dir}/sqlmap_$(basename "${url}")" || warning "SQLMap failed for ${url}"
            done < <(head -3 "${targets_file}")
        fi
    fi
}

# XSS testing
xss_testing() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/xss"
    mkdir -p "${output_dir}"
    
    info "Starting XSS testing"
    
    # Dalfox - XSS scanner
    if command -v dalfox &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running dalfox XSS scanner..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            dalfox url "${url}" --output "${output_dir}/dalfox_$(basename "${url}").txt" \
                  --silence --worker 10 || warning "Dalfox failed for ${url}"
        done < <(head -5 "${targets_file}")
        success "Dalfox XSS scanning completed"
    fi
}

# Subdomain takeover check
subdomain_takeover() {
    local subdomains_file="$1"
    local output_dir="${RESULTS_DIR}/takeover"
    mkdir -p "${output_dir}"
    
    info "Checking for subdomain takeovers"
    
    # Subjack - subdomain takeover scanner
    if command -v subjack &> /dev/null && [[ -f "${subdomains_file}" ]]; then
        info "Running subjack..."
        subjack -w "${subdomains_file}" -o "${output_dir}/subjack_results.txt" -ssl
        success "Subjack completed"
    fi
    
    # Subzy - subdomain takeover scanner
    if command -v subzy &> /dev/null && [[ -f "${subdomains_file}" ]]; then
        info "Running subzy..."
        subzy run --targets "${subdomains_file}" --output "${output_dir}/subzy_results.txt"
        success "Subzy completed"
    fi
}

# Technology detection
tech_detection() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/technology"
    mkdir -p "${output_dir}"
    
    info "Starting technology detection"
    
    # WhatWeb - web technology scanner
    if command -v whatweb &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running whatweb..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            whatweb "${url}" --log-brief="${output_dir}/whatweb_$(basename "${url}").txt" || warning "WhatWeb failed for ${url}"
        done < <(head -10 "${targets_file}")
        success "WhatWeb technology detection completed"
    fi
}

# Web crawling and URL collection
web_crawling() {
    local target_domain="$1"
    local output_dir="${RESULTS_DIR}/crawling"
    mkdir -p "${output_dir}"
    
    info "Starting web crawling for ${target_domain}"
    
    # GAU - Get All URLs from web archives
    if command -v gau &> /dev/null; then
        info "Running gau for URL collection..."
        gau "${target_domain}" > "${output_dir}/gau_urls.txt"
        success "GAU URL collection completed"
    fi
    
    # Waybackurls - Wayback Machine URL collection
    if command -v waybackurls &> /dev/null; then
        info "Running waybackurls..."
        waybackurls "${target_domain}" > "${output_dir}/wayback_urls.txt"
        success "Waybackurls completed"
    fi
    
    # Katana - web crawler
    if command -v katana &> /dev/null; then
        info "Running katana crawler..."
        echo "https://${target_domain}" | katana -o "${output_dir}/katana_urls.txt" -d 2 -silent
        success "Katana crawling completed"
    fi
    
    # Combine all URLs
    if ls "${output_dir}"/*.txt &> /dev/null; then
        cat "${output_dir}"/*.txt | sort -u > "${output_dir}/all_urls_${target_domain}.txt"
        local count=$(wc -l < "${output_dir}/all_urls_${target_domain}.txt")
        success "Collected ${count} unique URLs for ${target_domain}"
    fi
}

# Generate comprehensive report
generate_report() {
    local target="$1"
    local report_file="${RESULTS_DIR}/bug_bounty_report_${target}_${TIMESTAMP}.md"
    
    info "Generating comprehensive bug bounty report..."
    
    cat > "${report_file}" << EOF
# Bug Bounty Assessment Report - ${target}

**Generated:** $(date)
**Target:** ${target}

## Executive Summary

This report contains the results of automated bug bounty reconnaissance and vulnerability assessment.

## Subdomains Discovered

EOF
    
    if [[ -f "${RESULTS_DIR}/subdomains/all_subdomains_${target}.txt" ]]; then
        echo "- **Total Subdomains:** $(wc -l < "${RESULTS_DIR}/subdomains/all_subdomains_${target}.txt")" >> "${report_file}"
        echo "- **Live Hosts:** $(wc -l < "${RESULTS_DIR}/http/live_hosts.txt" 2>/dev/null || echo "0")" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

## Vulnerabilities Found

EOF
    
    if [[ -f "${RESULTS_DIR}/vulnerabilities/nuclei_results.txt" ]]; then
        local vuln_count=$(wc -l < "${RESULTS_DIR}/vulnerabilities/nuclei_results.txt")
        echo "- **Nuclei Vulnerabilities:** ${vuln_count}" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

## Technology Stack

EOF
    
    if [[ -d "${RESULTS_DIR}/technology" ]]; then
        echo "Technology detection results available in: \`${RESULTS_DIR}/technology/\`" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

## URLs and Endpoints

EOF
    
    if [[ -f "${RESULTS_DIR}/crawling/all_urls_${target}.txt" ]]; then
        local url_count=$(wc -l < "${RESULTS_DIR}/crawling/all_urls_${target}.txt")
        echo "- **Total URLs Collected:** ${url_count}" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

## Takeover Opportunities

EOF
    
    if [[ -f "${RESULTS_DIR}/takeover/subjack_results.txt" ]]; then
        local takeover_count=$(grep -c "VULNERABLE" "${RESULTS_DIR}/takeover/subjack_results.txt" 2>/dev/null || echo "0")
        echo "- **Potential Takeovers:** ${takeover_count}" >> "${report_file}"
    fi
    
    success "Report generated: ${report_file}"
}

# Main execution function
main() {
    local target="${1:-}"
    
    if [[ -z "${target}" ]]; then
        echo "Usage: $0 <target-domain>"
        echo "Example: $0 example.com"
        exit 1
    fi
    
    info "Starting bug bounty automation for ${target}"
    
    # Check tool availability
    check_tools
    
    # Phase 1: Reconnaissance
    info "=== Phase 1: Reconnaissance ==="
    subdomain_enum "${target}"
    
    local subdomains_file="${RESULTS_DIR}/subdomains/all_subdomains_${target}.txt"
    
    if [[ -f "${subdomains_file}" ]]; then
        port_scan "${subdomains_file}"
        http_probe "${subdomains_file}"
    fi
    
    # Phase 2: Discovery
    info "=== Phase 2: Discovery ==="
    local live_hosts="${RESULTS_DIR}/http/live_hosts.txt"
    
    if [[ -f "${live_hosts}" ]]; then
        directory_bruteforce "${live_hosts}"
        param_discovery "${live_hosts}"
        tech_detection "${live_hosts}"
    fi
    
    # Phase 3: Crawling
    info "=== Phase 3: Web Crawling ==="
    web_crawling "${target}"
    
    # Phase 4: Vulnerability Assessment
    info "=== Phase 4: Vulnerability Assessment ==="
    if [[ -f "${live_hosts}" ]]; then
        vuln_scan "${live_hosts}"
        xss_testing "${live_hosts}"
    fi
    
    if [[ -f "${subdomains_file}" ]]; then
        subdomain_takeover "${subdomains_file}"
    fi
    
    # Phase 5: Reporting
    info "=== Phase 5: Reporting ==="
    generate_report "${target}"
    
    success "Bug bounty automation completed for ${target}"
    info "Results available in: ${RESULTS_DIR}"
    info "Log file: ${LOG_FILE}"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi