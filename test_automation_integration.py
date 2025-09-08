#!/usr/bin/env python3
"""
Enhanced Automation Integration Test Suite
Tests the new ESLint integration, bug bounty commands, and automated testing chain
"""

import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path

def test_eslint_integration():
    """Test ESLint integration and configuration"""
    print("Testing ESLint integration...")
    
    # Check package.json exists
    package_json = Path("package.json")
    if not package_json.exists():
        print("✗ package.json not found")
        return False
    
    try:
        with open(package_json, 'r') as f:
            pkg_data = json.load(f)
        
        # Check required scripts
        scripts = pkg_data.get('scripts', {})
        required_scripts = ['lint', 'lint:check', 'lint:security']
        
        for script in required_scripts:
            if script not in scripts:
                print(f"✗ Missing npm script: {script}")
                return False
        
        # Check ESLint configuration files
        eslint_configs = ['.eslintrc.json', '.eslintrc-security.json']
        for config in eslint_configs:
            if not Path(config).exists():
                print(f"✗ Missing ESLint config: {config}")
                return False
        
        print("✓ ESLint integration configuration validated")
        return True
        
    except Exception as e:
        print(f"✗ ESLint integration test failed: {e}")
        return False

def test_bug_bounty_script():
    """Test bug bounty commands script"""
    print("Testing bug bounty commands script...")
    
    script_path = Path("bug_bounty_commands.sh")
    if not script_path.exists():
        print("✗ bug_bounty_commands.sh not found")
        return False
    
    # Check script is executable
    if not os.access(script_path, os.X_OK):
        print("✗ bug_bounty_commands.sh is not executable")
        return False
    
    # Test script syntax
    try:
        result = subprocess.run(
            ['bash', '-n', str(script_path)], 
            capture_output=True, 
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            print(f"✗ Script syntax error: {result.stderr}")
            return False
        
        # Check for required functions
        with open(script_path, 'r') as f:
            content = f.read()
        
        required_functions = [
            'subdomain_enum',
            'port_scan', 
            'http_probe',
            'vuln_scan',
            'generate_report'
        ]
        
        for func in required_functions:
            if func not in content:
                print(f"✗ Missing function: {func}")
                return False
        
        print("✓ Bug bounty script validated")
        return True
        
    except Exception as e:
        print(f"✗ Bug bounty script test failed: {e}")
        return False

def test_enhanced_application_features():
    """Test enhanced application features"""
    print("Testing enhanced application features...")
    
    try:
        # Import main application
        sys.path.insert(0, str(Path(__file__).parent))
        import bl4ckc3ll_p4nth30n as main
        
        # Check for new functions
        required_functions = [
            'run_eslint_security_check',
            'run_bug_bounty_automation', 
            'run_automated_testing_chain',
            'enhanced_subdomain_enum',
            'enhanced_port_scanning',
            'enhanced_tech_detection',
            'enhanced_web_crawling'
        ]
        
        for func_name in required_functions:
            if not hasattr(main, func_name):
                print(f"✗ Missing function: {func_name}")
                return False
        
        print("✓ Enhanced application features validated")
        return True
        
    except Exception as e:
        print(f"✗ Enhanced application features test failed: {e}")
        return False

def test_github_workflow_integration():
    """Test GitHub Actions workflow integration"""
    print("Testing GitHub Actions workflow integration...")
    
    workflow_path = Path(".github/workflows/security_scan.yml")
    if not workflow_path.exists():
        print("✗ GitHub workflow file not found")
        return False
    
    try:
        with open(workflow_path, 'r') as f:
            workflow_content = f.read()
        
        # Check for enhanced features
        required_elements = [
            'eslint-security',
            'Install ESLint dependencies',
            'Run ESLint security check',
            'Enhanced Testing Chain',
            'Bug Bounty Automation',
            'bug-bounty',
            'automated-chain'
        ]
        
        for element in required_elements:
            if element not in workflow_content:
                print(f"✗ Missing workflow element: {element}")
                return False
        
        print("✓ GitHub workflow integration validated")
        return True
        
    except Exception as e:
        print(f"✗ GitHub workflow test failed: {e}")
        return False

def test_automation_chain_integration():
    """Test that all automation components integrate properly"""
    print("Testing automation chain integration...")
    
    try:
        # Check configuration consistency
        config_path = Path("p4nth30n.cfg.json")
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Verify enhanced configuration sections
            enhanced_sections = ['eslint', 'bug_bounty', 'automation_chain']
            for section in enhanced_sections:
                if section not in config:
                    # This is not a failure, just a note
                    print(f"ℹ Configuration section '{section}' not found (optional)")
        
        # Test file dependencies
        critical_files = [
            'package.json',
            '.eslintrc.json', 
            'bug_bounty_commands.sh',
            '.github/workflows/security_scan.yml'
        ]
        
        for file_path in critical_files:
            if not Path(file_path).exists():
                print(f"✗ Critical file missing: {file_path}")
                return False
        
        print("✓ Automation chain integration validated")
        return True
        
    except Exception as e:
        print(f"✗ Automation chain integration test failed: {e}")
        return False

def test_security_and_compliance():
    """Test security features and compliance"""
    print("Testing security and compliance...")
    
    try:
        # Check ESLint security configuration
        eslint_security_config = Path(".eslintrc-security.json")
        if eslint_security_config.exists():
            with open(eslint_security_config, 'r') as f:
                config = json.load(f)
            
            # Verify security plugin is configured
            plugins = config.get('plugins', [])
            if 'security' not in plugins:
                print("✗ ESLint security plugin not configured")
                return False
            
            # Check for security rules
            rules = config.get('rules', {})
            security_rules = [rule for rule in rules.keys() if rule.startswith('security/')]
            if len(security_rules) < 5:
                print("✗ Insufficient security rules configured")
                return False
        
        # Check bug bounty script security
        bug_bounty_script = Path("bug_bounty_commands.sh")
        if bug_bounty_script.exists():
            with open(bug_bounty_script, 'r') as f:
                content = f.read()
            
            # Check for security practices
            if 'set -euo pipefail' not in content:
                print("⚠ Bug bounty script missing bash safety options")
            
            if 'timeout' not in content:
                print("⚠ Bug bounty script missing timeout controls")
        
        print("✓ Security and compliance validated")
        return True
        
    except Exception as e:
        print(f"✗ Security and compliance test failed: {e}")
        return False

def main():
    """Run all automation integration tests"""
    print("🔧 Bl4ckC3ll_PANTHEON Automation Integration Test Suite")
    print("=" * 60)
    
    tests = [
        ("ESLint Integration", test_eslint_integration),
        ("Bug Bounty Script", test_bug_bounty_script),
        ("Enhanced Application Features", test_enhanced_application_features),
        ("GitHub Workflow Integration", test_github_workflow_integration), 
        ("Automation Chain Integration", test_automation_chain_integration),
        ("Security and Compliance", test_security_and_compliance)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n🔍 {test_name}")
        print("-" * 40)
        try:
            result = test_func()
            results[test_name] = result
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"{status}")
        except Exception as e:
            print(f"❌ FAILED - Exception: {e}")
            results[test_name] = False
    
    # Summary
    print(f"\n📊 Test Results Summary")
    print("=" * 60)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED" 
        print(f"{test_name}: {status}")
    
    print(f"\n📈 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All automation integration tests PASSED!")
        return 0
    else:
        print("⚠️ Some tests failed - review implementation")
        return 1

if __name__ == "__main__":
    sys.exit(main())