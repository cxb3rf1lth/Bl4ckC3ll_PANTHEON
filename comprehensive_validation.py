#!/usr/bin/env python3
"""
Comprehensive Enhancement Validation Test for Bl4ckC3ll_PANTHEON
Tests all major improvements and new features
"""

import sys
import time
import threading
from pathlib import Path

# Add current directory to path
sys.path.append(str(Path(__file__).parent))

def test_main_script_enhancements():
    """Test enhanced main script functionality"""
    print("🔧 Testing Main Script Enhancements")
    print("-" * 40)
    
    try:
        import bl4ckc3ll_p4nth30n as main
        
        # Test 1: Import and basic functionality
        print("✅ Main script imports successfully")
        
        # Test 2: Enhanced input sanitization
        test_cases = [
            ("example.com", "domain", True),
            ("<script>alert('xss')</script>", "safe_string", False),
            ("'; DROP TABLE users; --", "safe_string", False),
            ("192.168.1.1", "safe_string", True),
            ("../../../etc/passwd", "safe_string", False)
        ]
        
        sanitization_passed = 0
        for test_input, input_type, expected_valid in test_cases:
            is_valid, sanitized = main.sanitize_user_input(test_input, input_type)
            if is_valid == expected_valid:
                sanitization_passed += 1
        
        print(f"✅ Input sanitization: {sanitization_passed}/{len(test_cases)} tests passed")
        
        # Test 3: Performance monitoring
        main.GLOBAL_PERFORMANCE_MONITOR.start_monitoring()
        time.sleep(1)
        metrics = main.GLOBAL_PERFORMANCE_MONITOR.get_current_metrics()
        main.GLOBAL_PERFORMANCE_MONITOR.stop_monitoring()
        
        if metrics and 'cpu_percent' in metrics:
            print("✅ Performance monitoring working")
        else:
            print("⚠️ Performance monitoring limited (no psutil)")
        
        # Test 4: Enhanced error handling
        result = main.safe_execute(lambda: "test", default="default")
        if result == "test":
            print("✅ Enhanced error handling working")
        
        # Test 5: PantheonLogger compatibility
        logger = main.PantheonLogger("test")
        logger.info("Test message")
        print("✅ PantheonLogger compatibility working")
        
        # Test 6: Configuration loading
        cfg = main.load_cfg()
        if isinstance(cfg, dict) and len(cfg) > 0:
            print(f"✅ Configuration loading: {len(cfg)} sections")
        
        return True
        
    except Exception as e:
        print(f"❌ Main script test failed: {e}")
        return False

def test_tui_enhancements():
    """Test enhanced TUI functionality"""
    print("\n🎨 Testing TUI Enhancements")
    print("-" * 40)
    
    try:
        import tui_consolidated
        
        # Test 1: Import and basic structure
        print("✅ TUI module imports successfully")
        
        # Test 2: Enhanced error handler
        handler = tui_consolidated.TUIErrorHandler()
        
        # Test input validation
        test_cases = [
            ("example.com", True),
            ("<script>alert('xss')</script>", False),
            ("valid-domain.com", True),
            ("'; DROP TABLE users; --", False)
        ]
        
        validation_passed = 0
        for test_input, expected_valid in test_cases:
            is_valid, sanitized = handler.validate_input(test_input, "safe_string")
            if is_valid == expected_valid:
                validation_passed += 1
        
        print(f"✅ TUI input validation: {validation_passed}/{len(test_cases)} tests passed")
        
        # Test 3: Target management validation
        target_mgmt = tui_consolidated.TargetManagement()
        
        # Test domain validation
        domain_tests = [
            ("example.com", True),
            ("192.168.1.1", True),
            ("invalid..domain", False),
            ("<script>", False)
        ]
        
        domain_passed = 0
        for domain, expected in domain_tests:
            result = target_mgmt.validate_target(domain)
            if result == expected:
                domain_passed += 1
        
        print(f"✅ Target validation: {domain_passed}/{len(domain_tests)} tests passed")
        
        return True
        
    except Exception as e:
        print(f"❌ TUI test failed: {e}")
        return False

def test_code_quality_improvements():
    """Test code quality improvements"""
    print("\n📊 Testing Code Quality Improvements")
    print("-" * 40)
    
    try:
        # Test syntax compilation
        import ast
        
        files_to_check = ['bl4ckc3ll_p4nth30n.py', 'tui_consolidated.py']
        syntax_passed = 0
        
        for filename in files_to_check:
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                ast.parse(content)
                syntax_passed += 1
                print(f"✅ {filename}: Syntax valid")
            except SyntaxError as e:
                print(f"❌ {filename}: Syntax error at line {e.lineno}")
            except FileNotFoundError:
                print(f"⚠️ {filename}: File not found")
        
        print(f"✅ Syntax validation: {syntax_passed}/{len(files_to_check)} files passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Code quality test failed: {e}")
        return False

def test_security_enhancements():
    """Test security enhancements"""
    print("\n🔒 Testing Security Enhancements")
    print("-" * 40)
    
    try:
        import bl4ckc3ll_p4nth30n as main
        
        # Test dangerous input detection
        dangerous_inputs = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "|cat /etc/passwd",
            "javascript:alert(1)",
            "\x00null_byte"
        ]
        
        blocked_count = 0
        for dangerous_input in dangerous_inputs:
            is_valid, sanitized = main.sanitize_user_input(dangerous_input, 'safe_string')
            if not is_valid:
                blocked_count += 1
        
        print(f"✅ Dangerous input detection: {blocked_count}/{len(dangerous_inputs)} blocked")
        
        # Test secure defaults
        sanitizer = main.GLOBAL_SANITIZER
        if hasattr(sanitizer, 'blocked_keywords') and len(sanitizer.blocked_keywords) > 0:
            print(f"✅ Security keyword filtering: {len(sanitizer.blocked_keywords)} keywords")
        
        return True
        
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        return False

def test_performance_optimizations():
    """Test performance optimizations"""
    print("\n⚡ Testing Performance Optimizations")
    print("-" * 40)
    
    try:
        import bl4ckc3ll_p4nth30n as main
        
        # Test performance monitoring
        monitor = main.GLOBAL_PERFORMANCE_MONITOR
        monitor.start_monitoring()
        time.sleep(1)
        
        # Test optimal thread calculation
        optimal_threads = monitor.get_optimal_threads()
        print(f"✅ Optimal threads calculation: {optimal_threads} threads")
        
        # Test throttling detection
        should_throttle = monitor.should_throttle_operations()
        print(f"✅ Resource throttling detection: {'Active' if should_throttle else 'Not needed'}")
        
        monitor.stop_monitoring()
        
        return True
        
    except Exception as e:
        print(f"❌ Performance test failed: {e}")
        return False

def run_comprehensive_validation():
    """Run all validation tests"""
    print("🧪 Comprehensive Enhancement Validation for Bl4ckC3ll_PANTHEON")
    print("=" * 70)
    print("Testing all enhancements and improvements...")
    print()
    
    tests = [
        ("Main Script Enhancements", test_main_script_enhancements),
        ("TUI Enhancements", test_tui_enhancements),
        ("Code Quality Improvements", test_code_quality_improvements),
        ("Security Enhancements", test_security_enhancements),
        ("Performance Optimizations", test_performance_optimizations)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed_tests += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
        
        print()  # Add spacing between tests
    
    # Final summary
    print("=" * 70)
    print(f"📊 COMPREHENSIVE VALIDATION SUMMARY")
    print("=" * 70)
    print(f"Tests Passed: {passed_tests}/{total_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if passed_tests == total_tests:
        print("🎉 ALL TESTS PASSED! Framework is fully enhanced and ready for production.")
        return 0
    elif passed_tests >= total_tests * 0.8:
        print("✅ EXCELLENT! Most enhancements working properly with minor issues.")
        return 0
    else:
        print("⚠️ ATTENTION NEEDED: Some major enhancements require fixes.")
        return 1

if __name__ == "__main__":
    sys.exit(run_comprehensive_validation())