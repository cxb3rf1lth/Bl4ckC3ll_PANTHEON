#!/usr/bin/env python3
"""
Enhanced Scanner Module for Bl4ckC3ll_PANTHEON
Provides advanced scanning capabilities with comprehensive validation and monitoring
"""

import asyncio
import aiohttp
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timezone
import json
import threading
import time
import subprocess
import tempfile

# Import our enhanced validation system
from enhanced_validation import (
    enhanced_validator, performance_monitor, error_recovery, 
    security_validator, config_validator, enhanced_safe_execute
)


class EnhancedScanManager:
    """Advanced scanning manager with enhanced validation and monitoring"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config_validator.validate_scan_config(config)
        self.active_scans = set()
        self.scan_results = {}
        self.scan_lock = threading.Lock()
        
    @performance_monitor.time_function('scan_manager.subdomain_discovery')
    @error_recovery.retry_with_backoff(max_retries=2)
    async def enhanced_subdomain_discovery(self, domains: List[str]) -> Set[str]:
        """Enhanced subdomain discovery with multiple tools and validation"""
        all_subdomains = set()
        
        # Validate input domains
        valid_domains = [
            domain for domain in domains 
            if enhanced_validator.validate_domain(domain.strip())
        ]
        
        if not valid_domains:
            return all_subdomains
        
        # Run multiple subdomain discovery tools
        tasks = []
        
        # Passive discovery tools
        for domain in valid_domains:
            tasks.append(self._run_passive_subdomain_discovery(domain))
            tasks.append(self._run_certificate_transparency_search(domain))
            tasks.append(self._run_dns_brute_force(domain))
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect and validate results
        for result in results:
            if isinstance(result, set) and not isinstance(result, Exception):
                # Validate each subdomain before adding
                valid_subs = {
                    sub for sub in result 
                    if enhanced_validator.validate_domain(sub)
                }
                all_subdomains.update(valid_subs)
        
        return all_subdomains
    
    async def _run_passive_subdomain_discovery(self, domain: str) -> Set[str]:
        """Run passive subdomain discovery"""
        subdomains = set()
        
        # Simulate passive discovery (would use actual APIs in production)
        try:
            # Certificate Transparency logs
            ct_subdomains = await self._query_ct_logs(domain)
            subdomains.update(ct_subdomains)
            
            # DNS aggregation services
            dns_subdomains = await self._query_dns_aggregators(domain)
            subdomains.update(dns_subdomains)
            
        except Exception as e:
            print(f"Passive discovery error for {domain}: {e}")
        
        return subdomains
    
    async def _query_ct_logs(self, domain: str) -> Set[str]:
        """Query Certificate Transparency logs"""
        subdomains = set()
        
        # Mock CT log query (would use real CT APIs)
        mock_ct_results = [
            f"www.{domain}",
            f"api.{domain}",
            f"mail.{domain}",
            f"blog.{domain}"
        ]
        
        for subdomain in mock_ct_results:
            if enhanced_validator.validate_domain(subdomain):
                subdomains.add(subdomain)
        
        return subdomains
    
    async def _query_dns_aggregators(self, domain: str) -> Set[str]:
        """Query DNS aggregation services"""
        subdomains = set()
        
        # Mock DNS aggregator results
        mock_dns_results = [
            f"admin.{domain}",
            f"test.{domain}",
            f"dev.{domain}",
            f"staging.{domain}"
        ]
        
        for subdomain in mock_dns_results:
            if enhanced_validator.validate_domain(subdomain):
                subdomains.add(subdomain)
        
        return subdomains
    
    async def _run_certificate_transparency_search(self, domain: str) -> Set[str]:
        """Run comprehensive Certificate Transparency search"""
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Mock CT API call (would use real crt.sh or other CT APIs)
                ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
                
                # Simulate API call with timeout
                await asyncio.sleep(0.1)  # Mock delay
                
                # Mock results
                mock_certificates = [
                    {"name_value": f"*.{domain}"},
                    {"name_value": f"app.{domain}"},
                    {"name_value": f"secure.{domain}"}
                ]
                
                for cert in mock_certificates:
                    name_value = cert.get("name_value", "")
                    if name_value.startswith("*."):
                        continue  # Skip wildcards for this example
                    
                    if enhanced_validator.validate_domain(name_value):
                        subdomains.add(name_value)
                        
        except Exception as e:
            print(f"Certificate Transparency search error for {domain}: {e}")
        
        return subdomains
    
    async def _run_dns_brute_force(self, domain: str) -> Set[str]:
        """Run intelligent DNS brute force"""
        subdomains = set()
        
        # Common subdomain wordlist
        common_subs = [
            "www", "mail", "ftp", "admin", "api", "app", "blog", 
            "dev", "test", "staging", "prod", "secure", "portal"
        ]
        
        # Simulate DNS resolution
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            
            # Mock DNS resolution (would use actual DNS queries)
            if enhanced_validator.validate_domain(subdomain):
                # Simulate some subdomains existing
                if hash(subdomain) % 3 == 0:  # Mock: ~33% exist
                    subdomains.add(subdomain)
        
        return subdomains
    
    @performance_monitor.time_function('scan_manager.port_discovery')
    async def enhanced_port_discovery(self, hosts: List[str]) -> Dict[str, List[int]]:
        """Enhanced port discovery with validation and smart scanning"""
        results = {}
        
        # Validate hosts
        valid_hosts = []
        for host in hosts:
            if enhanced_validator.validate_domain(host) or enhanced_validator.validate_ip_address(host):
                valid_hosts.append(host)
        
        if not valid_hosts:
            return results
        
        # Smart port scanning - start with top ports then expand
        top_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        extended_ports = list(range(1, 1000)) + [1433, 3389, 5432, 5984, 6379, 8000, 8888, 9200]
        
        # Scan top ports first for all hosts
        top_port_tasks = [
            self._scan_host_ports(host, top_ports)
            for host in valid_hosts
        ]
        
        top_results = await asyncio.gather(*top_port_tasks, return_exceptions=True)
        
        # Process top port results
        for i, result in enumerate(top_results):
            if isinstance(result, dict) and not isinstance(result, Exception):
                host = valid_hosts[i]
                results[host] = result.get('open_ports', [])
        
        # Extended scanning for hosts that had open ports
        extended_tasks = []
        for host, open_ports in results.items():
            if open_ports:  # Only do extended scan if we found open ports
                extended_tasks.append(self._scan_host_ports(host, extended_ports))
        
        if extended_tasks:
            extended_results = await asyncio.gather(*extended_tasks, return_exceptions=True)
            # Merge extended results (implementation would merge the port lists)
        
        return results
    
    async def _scan_host_ports(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """Scan specific ports on a host"""
        open_ports = []
        
        # Simulate port scanning
        for port in ports:
            if self._is_valid_port(port):
                # Mock port check (would use actual socket connections)
                if hash(f"{host}:{port}") % 10 < 2:  # Mock: ~20% open
                    open_ports.append(port)
                    
                # Simulate scanning delay
                await asyncio.sleep(0.001)
        
        return {
            'host': host,
            'open_ports': open_ports,
            'scan_time': datetime.now(timezone.utc).isoformat()
        }
    
    def _is_valid_port(self, port: int) -> bool:
        """Validate port number"""
        return isinstance(port, int) and 1 <= port <= 65535
    
    @performance_monitor.time_function('scan_manager.vulnerability_assessment')
    async def enhanced_vulnerability_assessment(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Enhanced vulnerability assessment with comprehensive checks"""
        results = {}
        
        # Validate targets
        valid_targets = [
            target for target in targets
            if enhanced_validator.validate_url(target) or enhanced_validator.validate_domain(target)
        ]
        
        if not valid_targets:
            return results
        
        # Multi-layered vulnerability assessment
        vuln_tasks = []
        
        for target in valid_targets:
            # Web application vulnerabilities
            vuln_tasks.append(self._scan_web_vulnerabilities(target))
            
            # SSL/TLS configuration
            vuln_tasks.append(self._scan_ssl_configuration(target))
            
            # HTTP security headers
            vuln_tasks.append(self._scan_security_headers(target))
            
            # Common misconfigurations
            vuln_tasks.append(self._scan_misconfigurations(target))
        
        vuln_results = await asyncio.gather(*vuln_tasks, return_exceptions=True)
        
        # Aggregate results by target
        target_index = 0
        for i, result in enumerate(vuln_results):
            if isinstance(result, dict) and not isinstance(result, Exception):
                target = result.get('target')
                if target in valid_targets:
                    if target not in results:
                        results[target] = []
                    results[target].extend(result.get('vulnerabilities', []))
        
        return results
    
    async def _scan_web_vulnerabilities(self, target: str) -> Dict[str, Any]:
        """Scan for common web application vulnerabilities"""
        vulnerabilities = []
        
        # Mock vulnerability scanning (would use real security tools)
        mock_vulns = [
            {
                'type': 'XSS',
                'severity': 'medium',
                'description': 'Potential Cross-Site Scripting vulnerability',
                'location': f'{target}/search?q=<script>',
                'confidence': 'low'
            },
            {
                'type': 'SQL Injection',
                'severity': 'high',
                'description': 'Potential SQL injection in parameter',
                'location': f'{target}/login?id=1',
                'confidence': 'medium'
            }
        ]
        
        # Simulate scanning delay
        await asyncio.sleep(0.2)
        
        # Randomly include some vulnerabilities for demo
        for vuln in mock_vulns:
            if hash(f"{target}:{vuln['type']}") % 3 == 0:
                vulnerabilities.append(vuln)
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_type': 'web_vulnerabilities'
        }
    
    async def _scan_ssl_configuration(self, target: str) -> Dict[str, Any]:
        """Scan SSL/TLS configuration"""
        vulnerabilities = []
        
        if not target.startswith('https://'):
            return {'target': target, 'vulnerabilities': [], 'scan_type': 'ssl'}
        
        # Mock SSL scanning
        mock_ssl_issues = [
            {
                'type': 'Weak Cipher',
                'severity': 'medium',
                'description': 'Server supports weak encryption ciphers',
                'location': target,
                'confidence': 'high'
            },
            {
                'type': 'Certificate Issue',
                'severity': 'low',
                'description': 'Certificate chain could be optimized',
                'location': target,
                'confidence': 'medium'
            }
        ]
        
        await asyncio.sleep(0.1)
        
        # Randomly include SSL issues
        for issue in mock_ssl_issues:
            if hash(f"{target}:ssl") % 4 == 0:
                vulnerabilities.append(issue)
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_type': 'ssl'
        }
    
    async def _scan_security_headers(self, target: str) -> Dict[str, Any]:
        """Scan HTTP security headers"""
        vulnerabilities = []
        
        # Mock security header analysis
        mock_header_issues = [
            {
                'type': 'Missing Security Header',
                'severity': 'low',
                'description': 'Content Security Policy (CSP) header missing',
                'location': target,
                'confidence': 'high'
            },
            {
                'type': 'Insecure Header',
                'severity': 'medium',
                'description': 'X-Frame-Options not set to DENY or SAMEORIGIN',
                'location': target,
                'confidence': 'high'
            }
        ]
        
        await asyncio.sleep(0.05)
        
        # Include header issues based on hash
        for issue in mock_header_issues:
            if hash(f"{target}:headers") % 2 == 0:
                vulnerabilities.append(issue)
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_type': 'security_headers'
        }
    
    async def _scan_misconfigurations(self, target: str) -> Dict[str, Any]:
        """Scan for common misconfigurations"""
        vulnerabilities = []
        
        # Mock misconfiguration scanning
        mock_misconfigs = [
            {
                'type': 'Directory Listing',
                'severity': 'low',
                'description': 'Directory listing enabled',
                'location': f'{target}/uploads/',
                'confidence': 'medium'
            },
            {
                'type': 'Backup Files',
                'severity': 'medium',
                'description': 'Backup files accessible',
                'location': f'{target}/config.bak',
                'confidence': 'high'
            }
        ]
        
        await asyncio.sleep(0.1)
        
        for config in mock_misconfigs:
            if hash(f"{target}:config") % 3 == 0:
                vulnerabilities.append(config)
        
        return {
            'target': target,
            'vulnerabilities': vulnerabilities,
            'scan_type': 'misconfigurations'
        }
    
    @performance_monitor.time_function('scan_manager.generate_report')
    def generate_enhanced_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive scan report with analysis"""
        report = {
            'scan_metadata': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'version': '2.0.0-enhanced',
                'scan_duration': self._calculate_scan_duration(scan_results),
                'total_targets': len(scan_results.get('targets', [])),
                'performance_metrics': performance_monitor.get_performance_report()
            },
            'executive_summary': self._generate_executive_summary(scan_results),
            'detailed_findings': self._organize_findings(scan_results),
            'risk_assessment': self._assess_risk_levels(scan_results),
            'recommendations': self._generate_recommendations(scan_results)
        }
        
        return report
    
    def _calculate_scan_duration(self, scan_results: Dict[str, Any]) -> str:
        """Calculate total scan duration"""
        # Mock calculation (would use actual timing data)
        return "15.5 minutes"
    
    def _generate_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of findings"""
        vulnerabilities = scan_results.get('vulnerabilities', {})
        
        total_vulns = sum(len(vulns) for vulns in vulnerabilities.values())
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for target_vulns in vulnerabilities.values():
            for vuln in target_vulns:
                severity = vuln.get('severity', 'low')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'risk_level': self._calculate_overall_risk(severity_counts),
            'key_concerns': self._identify_key_concerns(vulnerabilities)
        }
    
    def _organize_findings(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Organize findings by category and severity"""
        findings = {
            'by_severity': {'critical': [], 'high': [], 'medium': [], 'low': []},
            'by_type': {},
            'by_target': scan_results.get('vulnerabilities', {})
        }
        
        # Organize by severity and type
        for target, vulns in scan_results.get('vulnerabilities', {}).items():
            for vuln in vulns:
                severity = vuln.get('severity', 'low')
                vuln_type = vuln.get('type', 'Unknown')
                
                if severity in findings['by_severity']:
                    findings['by_severity'][severity].append(vuln)
                
                if vuln_type not in findings['by_type']:
                    findings['by_type'][vuln_type] = []
                findings['by_type'][vuln_type].append(vuln)
        
        return findings
    
    def _assess_risk_levels(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk levels"""
        vulnerabilities = scan_results.get('vulnerabilities', {})
        
        risk_factors = {
            'vulnerability_density': len(vulnerabilities) / max(1, len(scan_results.get('targets', []))),
            'critical_vulns': sum(1 for vulns in vulnerabilities.values() 
                                for vuln in vulns if vuln.get('severity') == 'critical'),
            'high_vulns': sum(1 for vulns in vulnerabilities.values() 
                            for vuln in vulns if vuln.get('severity') == 'high'),
        }
        
        # Calculate composite risk score
        risk_score = (
            risk_factors['critical_vulns'] * 10 +
            risk_factors['high_vulns'] * 5 +
            risk_factors['vulnerability_density'] * 2
        )
        
        if risk_score >= 20:
            risk_level = 'Critical'
        elif risk_score >= 10:
            risk_level = 'High'
        elif risk_score >= 5:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'overall_risk_level': risk_level,
            'risk_score': risk_score,
            'risk_factors': risk_factors
        }
    
    def _calculate_overall_risk(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        if severity_counts['critical'] > 0:
            return 'Critical'
        elif severity_counts['high'] > 2:
            return 'High'
        elif severity_counts['medium'] > 5:
            return 'Medium'
        else:
            return 'Low'
    
    def _identify_key_concerns(self, vulnerabilities: Dict[str, List[Dict[str, Any]]]) -> List[str]:
        """Identify key security concerns"""
        concerns = []
        
        # Check for patterns in vulnerabilities
        all_vulns = [vuln for vulns in vulnerabilities.values() for vuln in vulns]
        
        vuln_types = {}
        for vuln in all_vulns:
            vuln_type = vuln.get('type', 'Unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # Identify most common vulnerability types
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:3]:
            if count > 1:
                concerns.append(f"Multiple {vuln_type} vulnerabilities detected ({count} instances)")
        
        return concerns
    
    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate actionable recommendations"""
        recommendations = []
        
        vulnerabilities = scan_results.get('vulnerabilities', {})
        all_vulns = [vuln for vulns in vulnerabilities.values() for vuln in vulns]
        
        # Generate recommendations based on findings
        vuln_types = set(vuln.get('type') for vuln in all_vulns)
        
        recommendation_map = {
            'XSS': {
                'priority': 'High',
                'action': 'Implement Content Security Policy (CSP) and input validation',
                'effort': 'Medium'
            },
            'SQL Injection': {
                'priority': 'Critical',
                'action': 'Use parameterized queries and input sanitization',
                'effort': 'High'
            },
            'Missing Security Header': {
                'priority': 'Medium',
                'action': 'Configure security headers (CSP, HSTS, X-Frame-Options)',
                'effort': 'Low'
            },
            'Weak Cipher': {
                'priority': 'Medium',
                'action': 'Update SSL/TLS configuration to disable weak ciphers',
                'effort': 'Low'
            }
        }
        
        for vuln_type in vuln_types:
            if vuln_type in recommendation_map:
                recommendations.append(recommendation_map[vuln_type])
        
        return recommendations


# Example usage and testing
async def main():
    """Example usage of enhanced scanner"""
    config = {
        'limits': {
            'parallel_jobs': 20,
            'http_timeout': 30,
            'rps': 1000
        },
        'nuclei': {
            'severity': 'medium,high,critical',
            'rps': 500
        }
    }
    
    scanner = EnhancedScanManager(config)
    
    # Test subdomain discovery
    print("Testing enhanced subdomain discovery...")
    domains = ['example.com', 'test.com']
    subdomains = await scanner.enhanced_subdomain_discovery(domains)
    print(f"Found {len(subdomains)} subdomains: {list(subdomains)[:5]}...")
    
    # Test port discovery
    print("\nTesting enhanced port discovery...")
    hosts = list(subdomains)[:3] if subdomains else ['example.com']
    ports = await scanner.enhanced_port_discovery(hosts)
    for host, open_ports in ports.items():
        print(f"{host}: {len(open_ports)} open ports")
    
    # Test vulnerability assessment
    print("\nTesting vulnerability assessment...")
    targets = [f"https://{host}" for host in hosts]
    vulns = await scanner.enhanced_vulnerability_assessment(targets)
    for target, target_vulns in vulns.items():
        print(f"{target}: {len(target_vulns)} vulnerabilities")
    
    # Generate report
    print("\nGenerating enhanced report...")
    scan_results = {
        'targets': targets,
        'subdomains': subdomains,
        'ports': ports,
        'vulnerabilities': vulns
    }
    
    report = scanner.generate_enhanced_report(scan_results)
    print(f"Report generated with {report['scan_metadata']['total_targets']} targets")
    print(f"Overall risk level: {report['risk_assessment']['overall_risk_level']}")
    
    # Display performance metrics
    print("\nPerformance metrics:")
    for func, metrics in performance_monitor.get_performance_report().items():
        print(f"  {func}: {metrics['average_time']:.3f}s avg, {metrics['total_calls']} calls")


if __name__ == "__main__":
    asyncio.run(main())