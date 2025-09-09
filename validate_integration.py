#!/usr/bin/env python3
"""
Final Integration Validation Script
Validates all BCAR components work correctly with Bl4ckC3ll_PANTHEON
"""

import sys
import json
import time
import tempfile
from pathlib import Path
from datetime import datetime

def validate_imports():
    """Validate all imports work correctly"""
    print("🔍 Validating imports...")
    
    try:
        from bcar import BCARCore, PantheonBCARIntegration
        print("✅ BCAR imports: OK")
        return True
    except ImportError as e:
        print(f"❌ BCAR imports: FAILED - {e}")
        return False

def validate_bcar_functionality():
    """Test BCAR core functionality"""
    print("\n🧪 Testing BCAR core functionality...")
    
    try:
        from bcar import BCARCore
        bcar = BCARCore()
        
        # Test payload generation
        payloads = bcar.generate_reverse_shell_payloads("192.168.1.100", 4444)
        assert isinstance(payloads, dict)
        assert len(payloads) > 0
        assert 'bash' in payloads
        print("✅ Payload generation: OK")
        
        # Test wordlist functions
        subdomain_wordlist = bcar._get_default_subdomain_wordlist()
        fuzzing_wordlist = bcar._get_default_fuzzing_wordlist()
        assert len(subdomain_wordlist) > 50
        assert len(fuzzing_wordlist) > 50
        print("✅ Wordlist functions: OK")
        
        return True
        
    except Exception as e:
        print(f"❌ BCAR functionality: FAILED - {e}")
        return False

def validate_integration_functions():
    """Test Pantheon integration functions"""
    print("\n🔗 Testing Pantheon integration...")
    
    try:
        from bcar import PantheonBCARIntegration
        integration = PantheonBCARIntegration()
        
        # Test meterpreter payload generation
        meterpreter_payloads = integration.generate_meterpreter_payloads("10.0.0.1", 5555)
        assert isinstance(meterpreter_payloads, dict)
        assert len(meterpreter_payloads) > 0
        print("✅ Meterpreter payloads: OK")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration functions: FAILED - {e}")
        return False

def validate_wordlists():
    """Validate wordlist files"""
    print("\n📚 Validating wordlists...")
    
    wordlist_files = {
        'wordlists_extra/advanced_subdomains.txt': 200,
        'wordlists_extra/advanced_fuzzing_paths.txt': 300,
        'wordlists_extra/advanced_parameters.txt': 150,
        'payloads/reverse_shells.json': 5000  # bytes
    }
    
    all_good = True
    for file_path, min_size in wordlist_files.items():
        file_obj = Path(file_path)
        if file_obj.exists():
            if file_path.endswith('.json'):
                # Check JSON file size
                size = file_obj.stat().st_size
                if size >= min_size:
                    print(f"✅ {file_path}: OK ({size} bytes)")
                else:
                    print(f"❌ {file_path}: Too small ({size} bytes)")
                    all_good = False
            else:
                # Check text file line count
                with open(file_obj, 'r') as f:
                    lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                if len(lines) >= min_size:
                    print(f"✅ {file_path}: OK ({len(lines)} entries)")
                else:
                    print(f"❌ {file_path}: Too few entries ({len(lines)})")
                    all_good = False
        else:
            print(f"❌ {file_path}: Missing")
            all_good = False
    
    return all_good

def validate_main_script():
    """Validate main script integration"""
    print("\n🎯 Testing main script integration...")
    
    try:
        # Test syntax
        import py_compile
        py_compile.compile('bl4ckc3ll_p4nth30n.py', doraise=True)
        print("✅ Main script syntax: OK")
        
        # Test BCAR availability
        sys.path.insert(0, '.')
        import bl4ckc3ll_p4nth30n as main_script
        
        if hasattr(main_script, 'BCAR_AVAILABLE'):
            if main_script.BCAR_AVAILABLE:
                print("✅ BCAR integration: Available")
            else:
                print("⚠️  BCAR integration: Not available")
        else:
            print("❌ BCAR integration: Variable missing")
            return False
        
        # Check if new functions exist
        bcar_functions = [
            'run_bcar_enhanced_reconnaissance',
            'run_advanced_subdomain_takeover', 
            'run_automated_payload_injection',
            'run_comprehensive_fuzzing'
        ]
        
        for func_name in bcar_functions:
            if hasattr(main_script, func_name):
                print(f"✅ Function {func_name}: OK")
            else:
                print(f"❌ Function {func_name}: Missing")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ Main script validation: FAILED - {e}")
        return False

def validate_tui_integration():
    """Validate TUI integration"""
    print("\n🖥️  Testing TUI integration...")
    
    try:
        # Test TUI scanner options
        tui_file = Path('tui/screens/scan_runner.py')
        if tui_file.exists():
            with open(tui_file, 'r') as f:
                content = f.read()
            
            # Check if BCAR options are present
            bcar_options = ['BCAR Enhanced Recon', 'Subdomain Takeover', 'Advanced Fuzzing', 'Payload Injection']
            
            found_options = 0
            for option in bcar_options:
                if option in content:
                    found_options += 1
            
            if found_options == len(bcar_options):
                print("✅ TUI BCAR options: All present")
                return True
            else:
                print(f"⚠️  TUI BCAR options: {found_options}/{len(bcar_options)} found")
                return False
        else:
            print("❌ TUI scanner file: Missing")
            return False
            
    except Exception as e:
        print(f"❌ TUI validation: FAILED - {e}")
        return False

def run_end_to_end_test():
    """Run a complete end-to-end test"""
    print("\n🚀 Running end-to-end test...")
    
    try:
        from bcar import BCARCore
        
        # Create temporary directory for test
        with tempfile.TemporaryDirectory() as temp_dir:
            bcar = BCARCore()
            
            # Test a quick scan (mocked)
            test_config = {
                'ct_search': False,  # Skip real CT queries
                'subdomain_enum': False,  # Skip real DNS queries
                'takeover_check': False,
                'port_scan': False,
                'tech_detection': False,
                'directory_fuzz': False,
                'parameter_discovery': False
            }
            
            # This should complete quickly without external requests
            result = bcar.run_comprehensive_scan("test.local", test_config)
            
            assert isinstance(result, dict)
            assert 'domain' in result
            assert 'scan_time' in result
            
            print("✅ End-to-end test: OK")
            return True
            
    except Exception as e:
        print(f"❌ End-to-end test: FAILED - {e}")
        return False

def main():
    """Main validation function"""
    print("🎯 BL4CKC3LL PANTHEON + BCAR INTEGRATION VALIDATION")
    print("=" * 60)
    
    start_time = time.time()
    
    # Run all validation tests
    tests = [
        ("Import Validation", validate_imports),
        ("BCAR Functionality", validate_bcar_functionality),
        ("Integration Functions", validate_integration_functions),
        ("Wordlists & Payloads", validate_wordlists),
        ("Main Script Integration", validate_main_script),
        ("TUI Integration", validate_tui_integration),
        ("End-to-End Test", run_end_to_end_test)
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"\n❌ {test_name}: EXCEPTION - {e}")
            results[test_name] = False
    
    # Summary
    elapsed = time.time() - start_time
    passed = sum(results.values())
    total = len(results)
    
    print("\n" + "=" * 60)
    print("📋 VALIDATION SUMMARY")
    print("-" * 30)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:.<30} {status}")
    
    print("-" * 30)
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Success Rate: {passed/total*100:.1f}%")
    print(f"Elapsed Time: {elapsed:.1f}s")
    
    if passed == total:
        print("\n🎉 ALL VALIDATIONS PASSED! BCAR integration is ready for use.")
        return True
    else:
        print(f"\n⚠️  {total - passed} validation(s) failed. Please review and fix.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)