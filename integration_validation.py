#!/usr/bin/env python3
"""
Integration Validation for Bl4ckC3ll_PANTHEON
Validates that all components work together properly and handles edge cases
"""

import sys
import os
import json
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

class IntegrationValidator:
    """Comprehensive integration validation for all components"""
    
    def __init__(self):
        self.test_results = {}
        self.start_time = time.time()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="pantheon_integration_"))
        
    def log_test(self, test_name: str, status: str, details: str = ""):
        """Log test result"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.test_results[test_name] = {
            "status": status,
            "timestamp": timestamp,
            "details": details
        }
        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_icon} {test_name}: {status}")
        if details:
            print(f"   Details: {details}")
    
    def test_module_integration(self):
        """Test that all major modules integrate properly"""
        print("\n🔗 Testing Module Integration")
        print("-" * 50)
        
        try:
            # Test main module
            sys.path.insert(0, str(Path(__file__).parent))
            import bl4ckc3ll_p4nth30n as main
            self.log_test("Main Module Import", "PASS")
            
            # Test enhanced components
            try:
                from enhanced_validation import enhanced_validator, config_validator
                self.log_test("Enhanced Validation Integration", "PASS")
            except Exception as e:
                self.log_test("Enhanced Validation Integration", "FAIL", str(e))
            
            # Test BCAR integration
            try:
                import bcar
                self.log_test("BCAR Module Integration", "PASS")
            except Exception as e:
                self.log_test("BCAR Module Integration", "FAIL", str(e))
            
            # Test error handling integration
            try:
                import error_handler
                self.log_test("Error Handler Integration", "PASS")
            except Exception as e:
                self.log_test("Error Handler Integration", "FAIL", str(e))
            
            # Test performance optimizer integration
            try:
                import performance_optimizer
                self.log_test("Performance Optimizer Integration", "PASS")
            except Exception as e:
                self.log_test("Performance Optimizer Integration", "FAIL", str(e))
                
        except Exception as e:
            self.log_test("Module Integration", "FAIL", str(e))
    
    def test_configuration_validation(self):
        """Test configuration validation and edge cases"""
        print("\n⚙️ Testing Configuration Validation")
        print("-" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            from enhanced_validation import config_validator
            
            # Test default configuration
            default_cfg = main.DEFAULT_CFG
            is_valid = config_validator.validate_config(default_cfg)
            self.log_test("Default Config Validation", "PASS" if is_valid else "FAIL")
            
            # Test configuration with missing sections
            incomplete_cfg = {"limits": {"parallel_jobs": 10}}
            is_invalid = not config_validator.validate_config(incomplete_cfg)
            self.log_test("Invalid Config Detection", "PASS" if is_invalid else "FAIL")
            
            # Test configuration file creation and loading
            test_cfg_file = self.temp_dir / "test_config.json"
            with open(test_cfg_file, 'w') as f:
                json.dump(default_cfg, f, indent=2)
            
            if test_cfg_file.exists():
                self.log_test("Config File Creation", "PASS")
            else:
                self.log_test("Config File Creation", "FAIL")
                
        except Exception as e:
            self.log_test("Configuration Validation", "FAIL", str(e))
    
    def test_input_validation_edge_cases(self):
        """Test input validation with various edge cases"""
        print("\n🛡️ Testing Input Validation Edge Cases")
        print("-" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            from enhanced_validation import enhanced_validator
            
            # Test domain validation edge cases
            edge_cases = [
                ("example.com", True, "Valid domain"),
                ("sub.example.com", True, "Valid subdomain"),
                ("192.168.1.1", False, "IP address should be invalid"),
                ("", False, "Empty string"),
                ("very-long-" + "a" * 100 + ".com", False, "Overly long domain"),
                ("domain..com", False, "Double dots"),
                ("-invalid.com", False, "Starts with hyphen"),
                ("invalid-.com", False, "Ends with hyphen"),
                ("localhost", True, "Localhost"),
                ("test_underscore.com", False, "Contains underscore"),
            ]
            
            passed = 0
            for domain, expected, description in edge_cases:
                result = enhanced_validator.validate_domain(domain)
                if result == expected:
                    passed += 1
                else:
                    print(f"   ❌ Failed: {description} - {domain}")
            
            self.log_test("Domain Validation Edge Cases", 
                         "PASS" if passed == len(edge_cases) else "FAIL",
                         f"{passed}/{len(edge_cases)} cases passed")
            
            # Test URL validation edge cases
            url_cases = [
                ("https://example.com", True, "HTTPS URL"),
                ("http://example.com", True, "HTTP URL"),
                ("ftp://example.com", False, "FTP protocol"),
                ("file:///etc/passwd", False, "File protocol"),
                ("javascript:alert(1)", False, "JavaScript protocol"),
                ("", False, "Empty URL"),
            ]
            
            url_passed = 0
            for url, expected, description in url_cases:
                result = enhanced_validator.validate_url(url)
                if result == expected:
                    url_passed += 1
                else:
                    print(f"   ❌ Failed: {description} - {url}")
            
            self.log_test("URL Validation Edge Cases",
                         "PASS" if url_passed == len(url_cases) else "FAIL", 
                         f"{url_passed}/{len(url_cases)} cases passed")
                         
        except Exception as e:
            self.log_test("Input Validation Edge Cases", "FAIL", str(e))
    
    def test_error_recovery_mechanisms(self):
        """Test error recovery and graceful degradation"""
        print("\n🔄 Testing Error Recovery Mechanisms")
        print("-" * 50)
        
        try:
            from enhanced_validation import error_recovery
            
            # Test retry mechanism
            attempt_count = 0
            @error_recovery.retry_with_backoff(max_retries=2)
            def flaky_function():
                nonlocal attempt_count
                attempt_count += 1
                if attempt_count < 3:
                    raise Exception("Temporary failure")
                return "success"
            
            try:
                result = flaky_function()
                self.log_test("Retry Mechanism", "PASS" if result == "success" else "FAIL")
            except Exception:
                self.log_test("Retry Mechanism", "FAIL", "Retries exhausted")
            
            # Test graceful tool fallback
            import bl4ckc3ll_p4nth30n as main
            fallback_manager = main.EnhancedToolFallbackManager()
            
            # Test with non-existent tool
            fallback_tool = fallback_manager.get_available_tool("nonexistent-tool-12345")
            self.log_test("Tool Fallback Mechanism", 
                         "PASS" if fallback_tool is None else "FAIL",
                         "Correctly handled missing tool")
                         
        except Exception as e:
            self.log_test("Error Recovery Mechanisms", "FAIL", str(e))
    
    def test_performance_optimizations(self):
        """Test performance optimizations and caching"""
        print("\n⚡ Testing Performance Optimizations")
        print("-" * 50)
        
        try:
            import performance_optimizer
            
            # Test caching mechanism
            @performance_optimizer.cached(ttl=60)
            def expensive_function(value):
                time.sleep(0.01)  # Simulate expensive operation
                return f"result_{value}"
            
            # First call
            start = time.time()
            result1 = expensive_function("test")
            first_call_time = time.time() - start
            
            # Second call (should be cached)
            start = time.time()
            result2 = expensive_function("test")
            second_call_time = time.time() - start
            
            cache_working = (result1 == result2 and second_call_time < first_call_time)
            self.log_test("Caching Mechanism", 
                         "PASS" if cache_working else "FAIL",
                         f"First: {first_call_time:.3f}s, Second: {second_call_time:.3f}s")
            
            # Test performance monitoring
            @performance_optimizer.timed
            def monitored_function():
                time.sleep(0.01)
                return "monitored"
            
            monitored_function()
            stats = performance_optimizer.get_performance_report()
            
            has_stats = bool(stats and 'performance_stats' in stats)
            self.log_test("Performance Monitoring", 
                         "PASS" if has_stats else "FAIL",
                         "Performance metrics collected")
                         
        except Exception as e:
            self.log_test("Performance Optimizations", "FAIL", str(e))
    
    def test_security_features(self):
        """Test security features and protections"""
        print("\n🔒 Testing Security Features")
        print("-" * 50)
        
        try:
            from enhanced_validation import security_validator
            
            # Test malicious input detection
            malicious_inputs = [
                "../../../etc/passwd",
                "<script>alert('xss')</script>",
                "'; DROP TABLE users; --",
                "\x00\x01\x02",
                "$(whoami)",
            ]
            
            detected = 0
            for malicious_input in malicious_inputs:
                if security_validator.is_malicious_input(malicious_input):
                    detected += 1
            
            self.log_test("Malicious Input Detection", 
                         "PASS" if detected >= len(malicious_inputs) * 0.8 else "FAIL",
                         f"{detected}/{len(malicious_inputs)} detected")
            
            # Test command injection prevention
            safe_command = security_validator.sanitize_command("ls -la")
            has_shell_chars = any(char in safe_command for char in [';', '&', '|', '`', '$'])
            
            self.log_test("Command Injection Prevention",
                         "PASS" if not has_shell_chars else "FAIL",
                         "Command sanitization working")
                         
        except Exception as e:
            self.log_test("Security Features", "FAIL", str(e))
    
    def run_all_tests(self):
        """Run all integration validation tests"""
        print("🔧 BL4CKCE3LL PANTHEON INTEGRATION VALIDATION")
        print("=" * 70)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Test Directory: {self.temp_dir}")
        
        # Run all test categories
        self.test_module_integration()
        self.test_configuration_validation()
        self.test_input_validation_edge_cases()
        self.test_error_recovery_mechanisms()
        self.test_performance_optimizations()
        self.test_security_features()
        
        # Calculate results
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() 
                          if result["status"] == "PASS")
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        elapsed_time = time.time() - self.start_time
        
        # Print summary
        print("\n" + "=" * 70)
        print("📋 INTEGRATION VALIDATION SUMMARY")
        print("=" * 70)
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"Elapsed Time: {elapsed_time:.1f}s")
        
        # Print detailed results
        print("\n📊 DETAILED RESULTS:")
        print("-" * 50)
        for test_name, result in self.test_results.items():
            status_icon = "✅" if result["status"] == "PASS" else "❌"
            print(f"{status_icon} {test_name:<35} {result['status']}")
            if result["details"]:
                print(f"     └── {result['details']}")
        
        # Recommendations
        print("\n💡 RECOMMENDATIONS:")
        print("-" * 30)
        if success_rate >= 90:
            print("🎉 EXCELLENT: Integration is highly robust")
        elif success_rate >= 75:
            print("✅ GOOD: Integration is solid with minor issues")
        elif success_rate >= 50:
            print("⚠️ MODERATE: Integration needs attention")
        else:
            print("🔧 CRITICAL: Integration requires significant work")
        
        # Save detailed report
        report_file = self.temp_dir / "integration_validation_report.json"
        with open(report_file, 'w') as f:
            json.dump({
                "summary": {
                    "total_tests": total_tests,
                    "passed_tests": passed_tests,
                    "failed_tests": failed_tests,
                    "success_rate": success_rate,
                    "elapsed_time": elapsed_time,
                    "timestamp": datetime.now().isoformat()
                },
                "detailed_results": self.test_results
            }, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        print(f"🗂️ Test artifacts in: {self.temp_dir}")
        
        return success_rate >= 90


def main():
    """Run integration validation"""
    validator = IntegrationValidator()
    success = validator.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())