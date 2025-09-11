#!/usr/bin/env python3
"""
Production Validation Script for Bl4ckC3ll_PANTHEON
Final comprehensive testing and quality assurance
"""

import sys
import os
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

sys.path.insert(0, str(Path(__file__).parent))

class ProductionValidator:
    """Production-ready validation and quality assurance"""
    
    def __init__(self):
        self.validation_results = {}
        self.start_time = time.time()
        self.error_count = 0
        self.warning_count = 0
        
    def validate_system_requirements(self):
        """Validate system requirements and dependencies"""
        print("🔍 SYSTEM REQUIREMENTS VALIDATION")
        print("=" * 50)
        
        # Python version check
        python_version = sys.version_info
        if python_version >= (3, 9):
            print(f"✅ Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
            self.validation_results['python_version'] = "PASS"
        else:
            print(f"❌ Python version: {python_version.major}.{python_version.minor}.{python_version.micro} (requires 3.9+)")
            self.validation_results['python_version'] = "FAIL"
            self.error_count += 1
        
        # Critical dependencies
        critical_deps = ['requests', 'psutil', 'json', 'pathlib', 're', 'subprocess']
        missing_deps = []
        
        for dep in critical_deps:
            try:
                __import__(dep)
            except ImportError:
                missing_deps.append(dep)
        
        if not missing_deps:
            print(f"✅ Critical dependencies: All {len(critical_deps)} available")
            self.validation_results['critical_dependencies'] = "PASS"
        else:
            print(f"❌ Missing dependencies: {missing_deps}")
            self.validation_results['critical_dependencies'] = "FAIL"
            self.error_count += 1
        
        # File system permissions
        test_file = Path("test_permissions.tmp")
        try:
            test_file.write_text("test")
            test_file.unlink()
            print("✅ File system permissions: READ/WRITE access")
            self.validation_results['filesystem_permissions'] = "PASS"
        except Exception as e:
            print(f"❌ File system permissions: {e}")
            self.validation_results['filesystem_permissions'] = "FAIL"
            self.error_count += 1
        
        print()
    
    def validate_core_functionality(self):
        """Validate core application functionality"""
        print("⚡ CORE FUNCTIONALITY VALIDATION")
        print("=" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            # Test configuration loading
            try:
                cfg = main.load_cfg()
                if cfg and isinstance(cfg, dict) and len(cfg) > 0:
                    print(f"✅ Configuration loading: {len(cfg)} sections loaded")
                    self.validation_results['config_loading'] = "PASS"
                else:
                    print("❌ Configuration loading: Empty or invalid config")
                    self.validation_results['config_loading'] = "FAIL"
                    self.error_count += 1
            except Exception as e:
                print(f"❌ Configuration loading: {e}")
                self.validation_results['config_loading'] = "FAIL"
                self.error_count += 1
            
            # Test core functions
            core_functions = [
                'search_certificate_transparency',
                'validate_domain_input',
                'validate_ip_input',
                'auto_fix_missing_dependencies'
            ]
            
            available_functions = 0
            for func_name in core_functions:
                if hasattr(main, func_name) and callable(getattr(main, func_name)):
                    available_functions += 1
                else:
                    print(f"⚠️ Missing function: {func_name}")
                    self.warning_count += 1
            
            if available_functions == len(core_functions):
                print(f"✅ Core functions: {available_functions}/{len(core_functions)} available")
                self.validation_results['core_functions'] = "PASS"
            else:
                print(f"⚠️ Core functions: {available_functions}/{len(core_functions)} available")
                self.validation_results['core_functions'] = "WARN"
                self.warning_count += 1
            
            # Test security functions
            try:
                # Test domain validation
                valid_domain = main.validate_domain_input("example.com")
                invalid_domain = main.validate_domain_input("../invalid")
                
                if valid_domain and not invalid_domain:
                    print("✅ Security validation: Domain validation working")
                    self.validation_results['security_validation'] = "PASS"
                else:
                    print("⚠️ Security validation: Domain validation issues")
                    self.validation_results['security_validation'] = "WARN"
                    self.warning_count += 1
            except Exception as e:
                print(f"❌ Security validation: {e}")
                self.validation_results['security_validation'] = "FAIL"
                self.error_count += 1
            
        except ImportError as e:
            print(f"❌ Core module import: {e}")
            self.validation_results['core_import'] = "FAIL"
            self.error_count += 1
        
        print()
    
    def validate_security_modules(self):
        """Validate security-related modules"""
        print("🛡️ SECURITY MODULES VALIDATION")
        print("=" * 50)
        
        security_modules = [
            ('config_validator', 'Configuration validation'),
            ('security_utils', 'Security utilities'),
            ('error_handler', 'Error handling'),
            ('enhanced_validation', 'Enhanced validation')
        ]
        
        for module_name, description in security_modules:
            try:
                module = __import__(module_name)
                print(f"✅ {description}: Module loaded")
                self.validation_results[f'security_{module_name}'] = "PASS"
            except ImportError as e:
                print(f"❌ {description}: Import failed - {e}")
                self.validation_results[f'security_{module_name}'] = "FAIL"
                self.error_count += 1
            except Exception as e:
                print(f"⚠️ {description}: Warning - {e}")
                self.validation_results[f'security_{module_name}'] = "WARN"
                self.warning_count += 1
        
        # Test security utilities specifically
        try:
            from security_utils import InputValidator, NetworkValidator, RateLimiter
            
            # Test input validation
            validator = InputValidator()
            safe_test = validator.validate_input("safe_input")
            dangerous_test = validator.validate_input("<script>alert('xss')</script>")
            
            if safe_test and not dangerous_test:
                print("✅ Input validation: Safe/dangerous detection working")
                self.validation_results['input_validation'] = "PASS"
            else:
                print(f"⚠️ Input validation: Issues detected (safe={safe_test}, dangerous={dangerous_test})")
                self.validation_results['input_validation'] = "WARN"
                self.warning_count += 1
            
        except Exception as e:
            print(f"❌ Security utilities: {e}")
            self.validation_results['security_utilities'] = "FAIL"
            self.error_count += 1
        
        print()
    
    def validate_performance(self):
        """Validate performance characteristics"""
        print("⚡ PERFORMANCE VALIDATION")
        print("=" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            # Test configuration load performance
            start_time = time.time()
            for _ in range(10):
                cfg = main.load_cfg()
            avg_config_time = (time.time() - start_time) / 10
            
            if avg_config_time < 0.1:
                print(f"✅ Configuration load performance: {avg_config_time:.3f}s average")
                self.validation_results['config_performance'] = "PASS"
            else:
                print(f"⚠️ Configuration load performance: {avg_config_time:.3f}s (may be slow)")
                self.validation_results['config_performance'] = "WARN"
                self.warning_count += 1
            
            # Test memory usage
            try:
                import psutil
                process = psutil.Process()
                initial_memory = process.memory_info().rss
                
                # Perform some operations
                cfg = main.load_cfg()
                domain_test = main.validate_domain_input("test.com")
                
                final_memory = process.memory_info().rss
                memory_increase = (final_memory - initial_memory) / 1024  # KB
                
                if memory_increase < 1024:  # Less than 1MB
                    print(f"✅ Memory usage: {memory_increase:.1f}KB increase")
                    self.validation_results['memory_performance'] = "PASS"
                else:
                    print(f"⚠️ Memory usage: {memory_increase:.1f}KB increase (may be high)")
                    self.validation_results['memory_performance'] = "WARN"
                    self.warning_count += 1
                    
            except ImportError:
                print("⚠️ Memory monitoring not available (psutil not installed)")
                self.validation_results['memory_performance'] = "WARN"
                self.warning_count += 1
                
        except Exception as e:
            print(f"❌ Performance validation: {e}")
            self.validation_results['performance'] = "FAIL"
            self.error_count += 1
        
        print()
    
    def validate_integration_points(self):
        """Validate integration with external components"""
        print("🔗 INTEGRATION VALIDATION")  
        print("=" * 50)
        
        # Test BCAR integration
        try:
            import bl4ckc3ll_p4nth30n as main
            
            if main.BCAR_AVAILABLE:
                from bcar import PantheonBCARIntegration, BCARCore
                
                # Test basic BCAR functionality
                bcar_core = BCARCore()
                integration = PantheonBCARIntegration()
                
                # Test payload generation (should not require network)
                payloads = integration.generate_meterpreter_payloads("127.0.0.1", 4444)
                
                if payloads and len(payloads) > 0:
                    print(f"✅ BCAR integration: {len(payloads)} payloads generated")
                    self.validation_results['bcar_integration'] = "PASS"
                else:
                    print("⚠️ BCAR integration: No payloads generated")
                    self.validation_results['bcar_integration'] = "WARN"
                    self.warning_count += 1
            else:
                print("⚠️ BCAR integration: Not available")
                self.validation_results['bcar_integration'] = "WARN"
                self.warning_count += 1
                
        except Exception as e:
            print(f"❌ BCAR integration: {e}")
            self.validation_results['bcar_integration'] = "FAIL"
            self.error_count += 1
        
        # Test performance optimizer
        try:
            from performance_optimizer import performance_cache, performance_monitor
            
            cache_stats = performance_cache.stats()
            monitor_stats = performance_monitor.get_stats()
            
            print(f"✅ Performance optimizer: Cache and monitor available")
            self.validation_results['performance_optimizer'] = "PASS"
            
        except ImportError:
            print("⚠️ Performance optimizer: Not available")
            self.validation_results['performance_optimizer'] = "WARN"
            self.warning_count += 1
        except Exception as e:
            print(f"❌ Performance optimizer: {e}")
            self.validation_results['performance_optimizer'] = "FAIL"
            self.error_count += 1
        
        print()
    
    def validate_configuration_files(self):
        """Validate configuration and data files"""
        print("📁 CONFIGURATION FILES VALIDATION")
        print("=" * 50)
        
        critical_files = [
            ('p4nth30n.cfg.json', 'Main configuration'),
            ('requirements.txt', 'Dependencies list'),
            ('install.sh', 'Installation script')
        ]
        
        for filename, description in critical_files:
            file_path = Path(filename)
            if file_path.exists():
                try:
                    if filename.endswith('.json'):
                        # Validate JSON syntax
                        with open(file_path) as f:
                            json.load(f)
                        print(f"✅ {description}: Valid JSON syntax")
                    else:
                        # Check if readable
                        file_path.read_text()
                        print(f"✅ {description}: File readable")
                    
                    self.validation_results[f'file_{filename}'] = "PASS"
                except Exception as e:
                    print(f"❌ {description}: File error - {e}")
                    self.validation_results[f'file_{filename}'] = "FAIL"
                    self.error_count += 1
            else:
                print(f"⚠️ {description}: File not found")
                self.validation_results[f'file_{filename}'] = "WARN"
                self.warning_count += 1
        
        # Check directory structure
        critical_dirs = ['wordlists_extra', 'payloads', 'plugins', 'logs']
        
        for dirname in critical_dirs:
            dir_path = Path(dirname)
            if dir_path.exists() and dir_path.is_dir():
                print(f"✅ Directory: {dirname}")
                self.validation_results[f'dir_{dirname}'] = "PASS"
            else:
                print(f"⚠️ Directory missing: {dirname}")
                self.validation_results[f'dir_{dirname}'] = "WARN"
                self.warning_count += 1
        
        print()
    
    def run_production_validation(self):
        """Run complete production validation suite"""
        print("🎯 BL4CKC3LL PANTHEON PRODUCTION VALIDATION")
        print("=" * 80)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Python: {sys.version}")
        print()
        
        validation_methods = [
            self.validate_system_requirements,
            self.validate_core_functionality,
            self.validate_security_modules,
            self.validate_performance,
            self.validate_integration_points,
            self.validate_configuration_files
        ]
        
        for method in validation_methods:
            try:
                method()
            except Exception as e:
                method_name = method.__name__
                print(f"❌ VALIDATION METHOD FAILED: {method_name}")
                print(f"   Error: {e}")
                self.error_count += 1
        
        self.generate_production_report()
    
    def generate_production_report(self):
        """Generate final production validation report"""
        elapsed_time = time.time() - self.start_time
        
        print("=" * 80)
        print("📋 PRODUCTION VALIDATION SUMMARY")
        print("=" * 80)
        
        total_checks = len(self.validation_results)
        passed = sum(1 for result in self.validation_results.values() if result == "PASS")
        failed = sum(1 for result in self.validation_results.values() if result == "FAIL")
        warnings = sum(1 for result in self.validation_results.values() if result == "WARN")
        
        print(f"Total Checks: {total_checks}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️ Warnings: {warnings}")
        print(f"Success Rate: {(passed/total_checks)*100:.1f}%")
        print(f"Validation Time: {elapsed_time:.2f}s")
        
        # Detailed results
        print(f"\n📊 DETAILED VALIDATION RESULTS:")
        print("-" * 60)
        
        categories = {
            'System': ['python_version', 'critical_dependencies', 'filesystem_permissions'],
            'Core': ['config_loading', 'core_functions', 'security_validation'],
            'Security': ['security_config_validator', 'security_security_utils', 'input_validation'],
            'Performance': ['config_performance', 'memory_performance'],
            'Integration': ['bcar_integration', 'performance_optimizer'],
            'Files': ['file_p4nth30n.cfg.json', 'file_requirements.txt', 'dir_wordlists_extra']
        }
        
        for category, checks in categories.items():
            print(f"\n{category} Validation:")
            for check in checks:
                if check in self.validation_results:
                    result = self.validation_results[check]
                    icon = "✅" if result == "PASS" else "❌" if result == "FAIL" else "⚠️"
                    print(f"  {icon} {check}: {result}")
        
        # Overall assessment
        print(f"\n🎯 PRODUCTION READINESS ASSESSMENT:")
        print("-" * 45)
        
        if failed == 0 and warnings <= 2:
            print("🚀 PRODUCTION READY: System is ready for deployment")
            print("   • All critical systems operational")
            print("   • Security validations passed")
            print("   • Performance within acceptable limits")
        elif failed == 0 and warnings <= 5:
            print("✅ NEAR PRODUCTION READY: Minor issues to address")
            print(f"   • {warnings} warnings to review")
            print("   • Consider addressing warnings before deployment")
        elif failed <= 2:
            print("⚠️ NEEDS ATTENTION: Critical issues to resolve")
            print(f"   • {failed} critical failures")
            print(f"   • {warnings} warnings")
            print("   • Address failures before production deployment")
        else:
            print("❌ NOT PRODUCTION READY: Significant issues detected")
            print(f"   • {failed} critical failures")
            print(f"   • {warnings} warnings")
            print("   • Extensive fixes required before deployment")
        
        # Save validation report
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_checks": total_checks,
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "success_rate": (passed/total_checks)*100,
                "elapsed_time": elapsed_time
            },
            "results": self.validation_results,
            "assessment": "PRODUCTION_READY" if failed == 0 and warnings <= 2 else 
                         "NEAR_READY" if failed == 0 and warnings <= 5 else
                         "NEEDS_ATTENTION" if failed <= 2 else "NOT_READY"
        }
        
        report_file = Path("production_validation_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved: {report_file}")
        
        return report

def main():
    """Main validation runner"""
    validator = ProductionValidator()
    validator.run_production_validation()
    return 0

if __name__ == "__main__":
    sys.exit(main())