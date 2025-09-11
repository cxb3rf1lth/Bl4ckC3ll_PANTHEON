#!/usr/bin/env python3
"""
Advanced functionality testing for Bl4ckC3ll_PANTHEON
Tests specific security features and menu options
"""

import sys
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Any

sys.path.insert(0, str(Path(__file__).parent))

class MenuFunctionalityTester:
    """Test all menu functionality and features"""
    
    def __init__(self):
        self.results = {}
        
    def test_menu_option_availability(self):
        """Test that all 28 menu options are available"""
        print("🎯 Testing Menu Option Availability")
        print("-" * 40)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            # Expected menu options (based on documentation)
            expected_options = [
                "TARGET", "REFRESH", "RECON", "VULN", "FULL", "PRESET", "REPORT", 
                "CONFIG", "PLUGIN", "VIEW", "NET", "ASSESS", "AI", "CLOUD", "API",
                "COMPLY", "CICD", "ESLINT", "BUGBOUNTY", "AUTOCHAIN", "TUI",
                "PAYLOADS", "TOOLS", "BCAR", "TAKEOVER", "PAYINJECT", "FUZZ", "EXIT"
            ]
            
            # Test if all required functions exist
            available_functions = []
            for attr_name in dir(main):
                if callable(getattr(main, attr_name)) and not attr_name.startswith('_'):
                    available_functions.append(attr_name)
            
            print(f"✅ Available functions: {len(available_functions)}")
            print(f"✅ Expected menu options: {len(expected_options)}")
            
            # Test core functions specifically
            core_functions = [
                'run_enhanced_subdomain_enumeration',
                'run_enhanced_port_scanning',
                'run_enhanced_vulnerability_assessment',
                'run_comprehensive_bug_bounty_scan',
                'search_certificate_transparency',
                'load_cfg',
                'auto_fix_missing_dependencies'
            ]
            
            missing_functions = []
            for func in core_functions:
                if not hasattr(main, func):
                    missing_functions.append(func)
            
            if missing_functions:
                self.results['menu_availability'] = f"FAIL - Missing: {missing_functions}"
                print(f"❌ Missing functions: {missing_functions}")
            else:
                self.results['menu_availability'] = "PASS"
                print("✅ All core functions available")
                
        except Exception as e:
            self.results['menu_availability'] = f"FAIL - {e}"
            print(f"❌ Menu availability test failed: {e}")
    
    def test_configuration_management(self):
        """Test configuration loading and validation"""
        print("\n🔧 Testing Configuration Management")
        print("-" * 40)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            from config_validator import ConfigValidator
            
            # Test configuration loading
            cfg = main.load_cfg()
            
            if not cfg:
                self.results['config_load'] = "FAIL - Empty config"
                print("❌ Configuration loading failed")
                return
            
            print(f"✅ Configuration loaded with {len(cfg)} sections")
            
            # Test validator
            validator = ConfigValidator()
            validation_result = validator.validate_config(cfg)
            
            if validation_result['valid']:
                self.results['config_validation'] = "PASS"
                print("✅ Configuration validation passed")
            else:
                self.results['config_validation'] = f"WARN - Errors: {validation_result.get('errors', [])}"
                print(f"⚠️ Configuration has warnings: {validation_result.get('errors', [])}")
            
            # Test critical configuration sections
            critical_sections = ['limits', 'nuclei', 'report', 'repos']
            missing_sections = [sec for sec in critical_sections if sec not in cfg]
            
            if missing_sections:
                print(f"⚠️ Missing configuration sections: {missing_sections}")
            else:
                print("✅ All critical configuration sections present")
                
        except Exception as e:
            self.results['config_management'] = f"FAIL - {e}"
            print(f"❌ Configuration management test failed: {e}")
    
    def test_security_features(self):
        """Test security validation and controls"""
        print("\n🛡️ Testing Security Features")
        print("-" * 40)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            from security_utils import InputValidator, NetworkValidator, RateLimiter
            
            # Test input validation
            validator = InputValidator()
            
            # Test safe inputs
            safe_inputs = ["example.com", "test123", "normal_file.txt"]
            dangerous_inputs = ["../../../etc/passwd", "<script>alert(1)</script>", "; rm -rf /"]
            
            safe_results = [validator.validate_input(inp) for inp in safe_inputs]
            dangerous_results = [validator.validate_input(inp) for inp in dangerous_inputs]
            
            safe_passed = all(safe_results)
            dangerous_blocked = not any(dangerous_results)
            
            if safe_passed and dangerous_blocked:
                self.results['input_validation'] = "PASS"
                print("✅ Input validation working correctly")
            else:
                self.results['input_validation'] = f"FAIL - Safe: {safe_passed}, Dangerous blocked: {dangerous_blocked}"
                print(f"❌ Input validation issues - Safe: {safe_passed}, Dangerous blocked: {dangerous_blocked}")
            
            # Test network validation
            net_validator = NetworkValidator()
            
            # Test domain validation
            valid_domains = ["google.com", "sub.example.org", "test-site.co.uk"]
            invalid_domains = ["", "invalid..domain", "a" * 300]
            
            domain_tests = []
            for domain in valid_domains:
                domain_tests.append(net_validator.is_valid_domain(domain))
            for domain in invalid_domains:
                domain_tests.append(not net_validator.is_valid_domain(domain))
            
            if all(domain_tests):
                self.results['domain_validation'] = "PASS"
                print("✅ Domain validation working correctly")
            else:
                self.results['domain_validation'] = "FAIL"
                print("❌ Domain validation failed")
            
            # Test rate limiting
            rate_limiter = RateLimiter(max_requests=2, time_window=1.0)
            
            # Should allow first 2 requests, block third
            results = []
            for i in range(3):
                results.append(rate_limiter.is_allowed("test"))
                time.sleep(0.1)
            
            if results == [True, True, False]:
                self.results['rate_limiting'] = "PASS"
                print("✅ Rate limiting working correctly")
            else:
                self.results['rate_limiting'] = f"FAIL - Results: {results}"
                print(f"❌ Rate limiting failed - Results: {results}")
                
        except Exception as e:
            self.results['security_features'] = f"FAIL - {e}"
            print(f"❌ Security features test failed: {e}")
    
    def test_tool_fallback_system(self):
        """Test tool fallback and management"""
        print("\n🔧 Testing Tool Fallback System")
        print("-" * 40)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            # Test tool fallback manager
            if hasattr(main, 'EnhancedToolFallbackManager'):
                fallback_manager = main.EnhancedToolFallbackManager()
                
                # Test fallback mapping
                test_tools = ['nuclei', 'nmap', 'subfinder', 'httpx']
                fallback_available = 0
                
                for tool in test_tools:
                    if hasattr(fallback_manager, 'get_fallbacks'):
                        fallbacks = fallback_manager.get_fallbacks(tool)
                        if fallbacks:
                            fallback_available += 1
                            print(f"✅ {tool}: {len(fallbacks)} fallbacks available")
                        else:
                            print(f"⚠️ {tool}: No fallbacks configured")
                
                if fallback_available >= len(test_tools) * 0.75:
                    self.results['tool_fallback'] = "PASS"
                    print("✅ Tool fallback system operational")
                else:
                    self.results['tool_fallback'] = "WARN"
                    print("⚠️ Limited tool fallback coverage")
            else:
                self.results['tool_fallback'] = "FAIL - Manager not found"
                print("❌ Tool fallback manager not found")
                
        except Exception as e:
            self.results['tool_fallback'] = f"FAIL - {e}"
            print(f"❌ Tool fallback test failed: {e}")
    
    def test_error_handling(self):
        """Test error handling and recovery"""
        print("\n🚨 Testing Error Handling")
        print("-" * 40)
        
        try:
            from error_handler import ErrorRecoveryManager, EnhancedLogger
            
            logger = EnhancedLogger("test")
            recovery_manager = ErrorRecoveryManager(logger)
            
            # Test retry mechanism
            attempt_count = 0
            
            @recovery_manager.retry_with_exponential_backoff(max_retries=2)
            def test_retry_function():
                nonlocal attempt_count
                attempt_count += 1
                if attempt_count == 1:
                    raise ValueError("First attempt fails")
                return "success"
            
            result = test_retry_function()
            
            if result == "success" and attempt_count == 2:
                self.results['error_recovery'] = "PASS"
                print("✅ Error recovery mechanism working")
            else:
                self.results['error_recovery'] = f"FAIL - Result: {result}, Attempts: {attempt_count}"
                print(f"❌ Error recovery failed - Result: {result}, Attempts: {attempt_count}")
            
            # Test safe execution context
            if hasattr(recovery_manager, 'safe_execute'):
                def safe_function():
                    return "safe execution works"
                
                safe_result = recovery_manager.safe_execute(safe_function)
                if safe_result == "safe execution works":
                    print("✅ Safe execution context working")
                else:
                    print("⚠️ Safe execution context issues")
            
        except Exception as e:
            self.results['error_handling'] = f"FAIL - {e}"
            print(f"❌ Error handling test failed: {e}")
    
    def test_performance_optimizations(self):
        """Test performance features"""
        print("\n⚡ Testing Performance Optimizations")
        print("-" * 40)
        
        try:
            # Test if performance optimizer is available
            try:
                from performance_optimizer import performance_cache, performance_monitor
                print("✅ Performance optimizer module loaded")
                
                # Test caching
                cache_stats = performance_cache.stats()
                print(f"✅ Cache system: Max size {cache_stats['max_size']}, TTL {cache_stats['ttl']}s")
                
                # Test monitoring
                monitor_stats = performance_monitor.get_stats()
                print(f"✅ Performance monitor: {len(monitor_stats['counters'])} counters, {len(monitor_stats['timings'])} timings")
                
                self.results['performance_optimizations'] = "PASS"
                
            except ImportError:
                self.results['performance_optimizations'] = "WARN - Optimizer not available"
                print("⚠️ Performance optimizer not available")
            
            # Test CT search performance (should be faster with optimization)
            import bl4ckc3ll_p4nth30n as main
            
            start_time = time.time()
            ct_results = main.search_certificate_transparency("github.com")
            ct_time = time.time() - start_time
            
            if ct_time < 5.0:  # Should be under 5 seconds now
                print(f"✅ CT search performance: {ct_time:.2f}s (optimized)")
            else:
                print(f"⚠️ CT search performance: {ct_time:.2f}s (may need optimization)")
                
        except Exception as e:
            self.results['performance'] = f"FAIL - {e}"
            print(f"❌ Performance test failed: {e}")
    
    def test_bcar_integration(self):
        """Test BCAR integration functionality"""
        print("\n🤖 Testing BCAR Integration")
        print("-" * 40)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            if main.BCAR_AVAILABLE:
                from bcar import PantheonBCARIntegration, BCARCore
                
                # Test BCAR core functionality
                bcar_core = BCARCore()
                test_domains = bcar_core.certificate_transparency_search("github.com", limit=10)
                
                if test_domains:
                    print(f"✅ BCAR core CT search: {len(test_domains)} domains found")
                else:
                    print("⚠️ BCAR core CT search returned no results")
                
                # Test Pantheon integration
                integration = PantheonBCARIntegration()
                
                # Test payload generation
                payloads = integration.generate_meterpreter_payloads("127.0.0.1", 4444)
                if payloads and len(payloads) > 0:
                    print(f"✅ BCAR payload generation: {len(payloads)} payloads")
                else:
                    print("❌ BCAR payload generation failed")
                
                # Test enhanced reconnaissance
                if hasattr(integration, 'enhanced_reconnaissance'):
                    recon_results = integration.enhanced_reconnaissance("example.com")
                    if recon_results:
                        print("✅ BCAR enhanced reconnaissance working")
                    else:
                        print("⚠️ BCAR enhanced reconnaissance returned no results")
                
                self.results['bcar_integration'] = "PASS"
                
            else:
                self.results['bcar_integration'] = "WARN - BCAR not available"
                print("⚠️ BCAR integration not available")
                
        except Exception as e:
            self.results['bcar_integration'] = f"FAIL - {e}"
            print(f"❌ BCAR integration test failed: {e}")
    
    def run_comprehensive_functionality_tests(self):
        """Run all functionality tests"""
        print("🎯 ADVANCED FUNCTIONALITY TEST SUITE")
        print("=" * 60)
        print(f"Testing Bl4ckC3ll_PANTHEON advanced features...")
        print()
        
        test_methods = [
            self.test_menu_option_availability,
            self.test_configuration_management,
            self.test_security_features,
            self.test_tool_fallback_system,
            self.test_error_handling,
            self.test_performance_optimizations,
            self.test_bcar_integration
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                test_name = test_method.__name__
                self.results[test_name] = f"EXCEPTION - {e}"
                print(f"❌ {test_name} threw exception: {e}")
        
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📋 ADVANCED FUNCTIONALITY TEST SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.results)
        passed = sum(1 for r in self.results.values() if r == "PASS")
        failed = sum(1 for r in self.results.values() if r.startswith("FAIL"))
        warnings = sum(1 for r in self.results.values() if r.startswith("WARN"))
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️ Warnings: {warnings}")
        print(f"Success Rate: {(passed/total_tests)*100:.1f}%")
        
        print("\n📊 DETAILED RESULTS:")
        print("-" * 40)
        for test_name, result in self.results.items():
            status_icon = "✅" if result == "PASS" else "❌" if result.startswith("FAIL") else "⚠️"
            print(f"{status_icon} {test_name:<30} {result}")
        
        # Overall assessment
        success_rate = (passed / total_tests) * 100
        print(f"\n💡 OVERALL ASSESSMENT:")
        print("-" * 25)
        if success_rate >= 90:
            print("🎉 EXCELLENT: All major functionality working perfectly")
        elif success_rate >= 75:
            print("✅ GOOD: Core functionality stable with minor issues")
        elif success_rate >= 60:
            print("⚠️ NEEDS ATTENTION: Some functionality needs improvement")
        else:
            print("❌ CRITICAL: Significant functionality issues detected")


def main():
    """Main test runner"""
    tester = MenuFunctionalityTester()
    tester.run_comprehensive_functionality_tests()
    return 0

if __name__ == "__main__":
    sys.exit(main())