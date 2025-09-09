#!/usr/bin/env python3
"""
Integration Example: Enhanced Bl4ckC3ll_PANTHEON Scanner
Demonstrates integration of enhanced modules with the main scanner
"""

import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

# Import existing scanner
sys.path.insert(0, str(Path(__file__).parent))
import bl4ckc3ll_p4nth30n as main_scanner

# Import our enhanced modules
from enhanced_validation import (
    enhanced_validator, performance_monitor, error_recovery,
    security_validator, config_validator, enhanced_safe_execute
)
from enhanced_scanner import EnhancedScanManager


class IntegratedScanner:
    """Integrated scanner combining original and enhanced functionality"""
    
    def __init__(self, config_file: str = None):
        """Initialize with enhanced validation and monitoring"""
        
        # Load and validate configuration
        if config_file and Path(config_file).exists():
            with open(config_file, 'r') as f:
                raw_config = json.load(f)
        else:
            raw_config = main_scanner.DEFAULT_CFG
        
        # Validate configuration with enhanced validator
        self.config = config_validator.validate_scan_config(raw_config)
        
        # Initialize enhanced scanner
        self.enhanced_scanner = EnhancedScanManager(self.config)
        
        # Initialize original scanner components
        self.logger = main_scanner.Logger()
        
        print("🚀 Integrated Bl4ckC3ll_PANTHEON Scanner initialized")
        print(f"📊 Configuration validated with {len(self.config)} sections")
    
    @performance_monitor.time_function('integrated_scanner.full_scan')
    async def run_enhanced_full_scan(self, targets: list) -> dict:
        """Run full enhanced scan with comprehensive validation"""
        
        print(f"🎯 Starting enhanced scan of {len(targets)} targets")
        
        # Validate all targets first
        validated_targets = []
        for target in targets:
            target = target.strip()
            if enhanced_validator.validate_domain(target) or enhanced_validator.validate_url(target):
                validated_targets.append(target)
                print(f"✅ Target validated: {target}")
            else:
                print(f"❌ Invalid target skipped: {target}")
        
        if not validated_targets:
            print("⚠️ No valid targets found!")
            return {}
        
        results = {
            'scan_metadata': {
                'start_time': datetime.now(timezone.utc).isoformat(),
                'total_targets': len(validated_targets),
                'validated_targets': validated_targets
            },
            'results': {}
        }
        
        try:
            # Phase 1: Enhanced Subdomain Discovery
            print("\n🔍 Phase 1: Enhanced Subdomain Discovery")
            domains = [t.replace('https://', '').replace('http://', '').split('/')[0] 
                      for t in validated_targets]
            subdomains = await self.enhanced_scanner.enhanced_subdomain_discovery(domains)
            results['results']['subdomains'] = list(subdomains)
            print(f"   Found {len(subdomains)} subdomains")
            
            # Phase 2: Enhanced Port Discovery  
            print("\n🔌 Phase 2: Enhanced Port Discovery")
            hosts = list(subdomains)[:10]  # Limit for demo
            if hosts:
                port_results = await self.enhanced_scanner.enhanced_port_discovery(hosts)
                results['results']['ports'] = port_results
                total_ports = sum(len(ports) for ports in port_results.values())
                print(f"   Scanned {len(hosts)} hosts, found {total_ports} open ports")
            
            # Phase 3: Enhanced Vulnerability Assessment
            print("\n🛡️ Phase 3: Enhanced Vulnerability Assessment")
            scan_targets = [f"https://{host}" for host in hosts[:5]]  # Top 5 hosts
            if scan_targets:
                vuln_results = await self.enhanced_scanner.enhanced_vulnerability_assessment(scan_targets)
                results['results']['vulnerabilities'] = vuln_results
                total_vulns = sum(len(vulns) for vulns in vuln_results.values())
                print(f"   Assessed {len(scan_targets)} targets, found {total_vulns} vulnerabilities")
            
            # Phase 4: Enhanced Report Generation
            print("\n📊 Phase 4: Enhanced Report Generation")
            report = self.enhanced_scanner.generate_enhanced_report(results['results'])
            results['report'] = report
            
            # Display summary
            self._display_scan_summary(results)
            
        except Exception as e:
            print(f"❌ Scan error: {e}")
            results['error'] = str(e)
        
        results['scan_metadata']['end_time'] = datetime.now(timezone.utc).isoformat()
        return results
    
    def _display_scan_summary(self, results: dict):
        """Display comprehensive scan summary"""
        print("\n" + "="*60)
        print("📋 ENHANCED SCAN SUMMARY")
        print("="*60)
        
        report = results.get('report', {})
        summary = report.get('executive_summary', {})
        
        # Basic statistics
        subdomains = results['results'].get('subdomains', [])
        ports = results['results'].get('ports', {})
        vulnerabilities = results['results'].get('vulnerabilities', {})
        
        print(f"🎯 Targets Scanned: {results['scan_metadata']['total_targets']}")
        print(f"🔍 Subdomains Found: {len(subdomains)}")
        print(f"🔌 Hosts with Open Ports: {len(ports)}")
        print(f"🛡️ Vulnerability Assessment: {len(vulnerabilities)} targets assessed")
        
        if summary:
            print(f"\n📊 VULNERABILITY SUMMARY")
            print(f"   Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
            
            severity_breakdown = summary.get('severity_breakdown', {})
            for severity, count in severity_breakdown.items():
                if count > 0:
                    emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
                    print(f"   {emoji} {severity.title()}: {count}")
            
            print(f"   Overall Risk Level: {summary.get('risk_level', 'Unknown')}")
        
        # Performance metrics
        print(f"\n⚡ PERFORMANCE METRICS")
        perf_report = performance_monitor.get_performance_report()
        for func, metrics in perf_report.items():
            if 'integrated_scanner' in func or 'scan_manager' in func:
                print(f"   {func}: {metrics['average_time']:.3f}s avg")
        
        print("="*60)
    
    def validate_targets_file(self, file_path: str) -> list:
        """Validate targets from file using enhanced validation"""
        targets = []
        
        if not Path(file_path).exists():
            print(f"❌ Targets file not found: {file_path}")
            return targets
        
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                target = line.strip()
                if not target or target.startswith('#'):
                    continue
                
                # Enhanced validation
                if enhanced_validator.validate_domain(target) or enhanced_validator.validate_url(target):
                    targets.append(target)
                else:
                    print(f"⚠️ Invalid target format: {target}")
            
        except Exception as e:
            print(f"❌ Error reading targets file: {e}")
        
        return targets
    
    @enhanced_safe_execute
    def run_integrated_scan_cli(self):
        """CLI interface for integrated scanner"""
        print("🛡️ Bl4ckC3ll_PANTHEON Enhanced Scanner")
        print("=" * 50)
        
        # Get targets
        targets_input = input("Enter targets (comma-separated) or file path: ").strip()
        
        if Path(targets_input).exists():
            targets = self.validate_targets_file(targets_input)
        else:
            targets = [t.strip() for t in targets_input.split(',') if t.strip()]
        
        if not targets:
            print("❌ No valid targets provided")
            return
        
        # Run scan
        try:
            results = asyncio.run(self.run_enhanced_full_scan(targets))
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            results_file = f"enhanced_scan_results_{timestamp}.json"
            
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\n💾 Results saved to: {results_file}")
            
        except KeyboardInterrupt:
            print("\n⚠️ Scan interrupted by user")
        except Exception as e:
            print(f"\n❌ Scan failed: {e}")


async def demo_enhanced_scanner():
    """Demonstrate enhanced scanner capabilities"""
    print("🎯 Enhanced Scanner Demonstration")
    print("="*50)
    
    # Initialize scanner
    scanner = IntegratedScanner()
    
    # Demo targets
    demo_targets = [
        'example.com',
        'https://test.com',
        'demo.org'
    ]
    
    print(f"🚀 Running demo scan with targets: {demo_targets}")
    
    # Run enhanced scan
    results = await scanner.run_enhanced_full_scan(demo_targets)
    
    # Show performance summary
    print(f"\n📈 Final Performance Report:")
    perf_report = performance_monitor.get_performance_report()
    
    for func, metrics in perf_report.items():
        success_rate = metrics.get('success_rate', 0) * 100
        print(f"  📊 {func}")
        print(f"     ⏱️  Average Time: {metrics['average_time']:.3f}s")
        print(f"     ✅ Success Rate: {success_rate:.1f}%")
        print(f"     🔄 Total Calls: {metrics['total_calls']}")
    
    return results


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        # CLI mode
        scanner = IntegratedScanner()
        scanner.run_integrated_scan_cli()
    else:
        # Demo mode
        print("Running enhanced scanner demonstration...")
        print("(Use --cli flag for interactive mode)")
        print()
        asyncio.run(demo_enhanced_scanner())