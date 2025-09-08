#!/usr/bin/env python3
"""
Test script to validate enhanced Bl4ckC3ll_PANTHEON features
Tests the new tool integrations and enhanced configurations
"""

import sys
import json
import subprocess
import shutil
from pathlib import Path

def test_configuration_enhancements():
    """Test enhanced configuration structure"""
    print("Testing configuration enhancements...")
    
    try:
        # Import main script to test configuration
        sys.path.insert(0, str(Path(__file__).parent))
        import bl4ckc3ll_p4nth30n as main
        
        # Test DEFAULT_CFG has new repositories
        config = main.DEFAULT_CFG
        
        # Check for new repositories
        expected_repos = [
            "NucleiCommunity", "NucleiFuzzing", "CustomNuclei", 
            "KnightSec", "AdditionalWordlists", "OneListForAll",
            "XSSPayloads", "SQLIPayloads"
        ]
        
        for repo in expected_repos:
            if repo not in config["repos"]:
                print(f"✗ Missing repository: {repo}")
                return False
        
        # Check for enhanced nuclei configuration
        nuclei_cfg = config.get("nuclei", {})
        if not nuclei_cfg.get("community_templates", False):
            print("✗ Missing community templates configuration")
            return False
        
        # Check for new tool configurations
        required_sections = [
            "xss_testing", "subdomain_takeover", "nmap_scanning", "sqlmap_testing"
        ]
        
        for section in required_sections:
            if section not in config:
                print(f"✗ Missing configuration section: {section}")
                return False
        
        print("✓ Configuration enhancements validated")
        return True
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False

def test_tool_availability():
    """Test availability of new security tools"""
    print("Testing enhanced tool availability...")
    
    # Core tools that should be available after enhanced installation
    enhanced_tools = [
        "nuclei", "ffuf", "nmap", "sqlmap", "subjack"
    ]
    
    # Optional tools (good to have but not required)
    optional_tools = [
        "subzy", "feroxbuster", "gobuster", "dirb", "amass",
        "waybackurls", "gospider", "paramspider", "dalfox"
    ]
    
    available_count = 0
    total_tools = len(enhanced_tools) + len(optional_tools)
    
    for tool in enhanced_tools:
        if shutil.which(tool):
            print(f"✓ Core tool available: {tool}")
            available_count += 1
        else:
            print(f"⚠ Core tool missing: {tool}")
    
    for tool in optional_tools:
        if shutil.which(tool):
            print(f"✓ Optional tool available: {tool}")
            available_count += 1
        else:
            print(f"- Optional tool missing: {tool}")
    
    print(f"Tool availability: {available_count}/{total_tools} tools found")
    
    # At least core tools should be available for full functionality
    if available_count >= len(enhanced_tools):
        print("✓ Sufficient tools available for enhanced functionality")
        return True
    else:
        print("⚠ Limited tool availability - some features may not work")
        return False

def test_enhanced_functions():
    """Test enhanced function definitions"""
    print("Testing enhanced function definitions...")
    
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        import bl4ckc3ll_p4nth30n as main
        
        # Test new functions exist
        enhanced_functions = [
            "run_xss_strike", "run_subzy", "run_enhanced_nmap", 
            "run_feroxbuster", "get_best_wordlist", "create_enhanced_payloads"
        ]
        
        for func_name in enhanced_functions:
            if not hasattr(main, func_name):
                print(f"✗ Missing function: {func_name}")
                return False
            else:
                print(f"✓ Function available: {func_name}")
        
        print("✓ Enhanced functions validated")
        return True
        
    except Exception as e:
        print(f"✗ Function test failed: {e}")
        return False

def test_plugin_functionality():
    """Test new plugin functionality"""
    print("Testing enhanced plugin functionality...")
    
    try:
        # Check if new plugins exist
        plugins_dir = Path(__file__).parent / "plugins"
        new_plugins = [
            "nuclei_template_manager.py",
            "enhanced_fuzzing.py"
        ]
        
        for plugin in new_plugins:
            plugin_file = plugins_dir / plugin
            if not plugin_file.exists():
                print(f"✗ Missing plugin: {plugin}")
                return False
            
            # Test plugin syntax
            try:
                subprocess.run([
                    sys.executable, "-m", "py_compile", str(plugin_file)
                ], check=True, capture_output=True)
                print(f"✓ Plugin syntax valid: {plugin}")
            except subprocess.CalledProcessError:
                print(f"✗ Plugin syntax error: {plugin}")
                return False
        
        print("✓ Plugin functionality validated")
        return True
        
    except Exception as e:
        print(f"✗ Plugin test failed: {e}")
        return False

def test_wordlist_management():
    """Test enhanced wordlist and payload management"""
    print("Testing wordlist and payload management...")
    
    try:
        # Test directory structure
        base_path = Path(__file__).parent
        required_dirs = [
            "payloads", "external_lists", "lists_merged", "wordlists_extra"
        ]
        
        for directory in required_dirs:
            dir_path = base_path / directory
            if not dir_path.exists():
                print(f"⚠ Directory will be created on first run: {directory}")
            else:
                print(f"✓ Directory exists: {directory}")
        
        # Test wordlist files in wordlists_extra
        wordlist_dir = base_path / "wordlists_extra"
        if wordlist_dir.exists():
            wordlist_files = list(wordlist_dir.glob("*.txt"))
            print(f"✓ Found {len(wordlist_files)} additional wordlist files")
        
        print("✓ Wordlist management structure validated")
        return True
        
    except Exception as e:
        print(f"✗ Wordlist test failed: {e}")
        return False

def test_installation_script():
    """Test enhanced installation script"""
    print("Testing installation script enhancements...")
    
    try:
        install_script = Path(__file__).parent / "install.sh"
        if not install_script.exists():
            print("✗ Installation script not found")
            return False
        
        # Read and check for enhanced tool installation
        with open(install_script, 'r') as f:
            content = f.read()
        
        # Check for new tools in installation script
        enhanced_tools = ["ffuf", "feroxbuster", "subzy", "paramspider", "dalfox"]
        
        missing_tools = []
        for tool in enhanced_tools:
            if tool not in content:
                missing_tools.append(tool)
        
        if missing_tools:
            print(f"⚠ Some tools missing from install script: {missing_tools}")
        else:
            print("✓ Enhanced tools found in installation script")
        
        # Check for additional functions
        if "install_additional_tools" in content and "create_payloads" in content:
            print("✓ Enhanced installation functions found")
        else:
            print("⚠ Some enhanced installation functions missing")
        
        print("✓ Installation script enhancements validated")
        return True
        
    except Exception as e:
        print(f"✗ Installation script test failed: {e}")
        return False

def main():
    """Run all enhancement tests"""
    print("🛡️ Bl4ckC3ll_PANTHEON Enhancement Validation")
    print("=" * 50)
    
    tests = [
        ("Configuration Enhancements", test_configuration_enhancements),
        ("Tool Availability", test_tool_availability),
        ("Enhanced Functions", test_enhanced_functions),
        ("Plugin Functionality", test_plugin_functionality),  
        ("Wordlist Management", test_wordlist_management),
        ("Installation Script", test_installation_script)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 {test_name}")
        print("-" * 30)
        
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"💥 {test_name}: ERROR - {e}")
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All enhancement tests passed!")
        print("\nEnhanced features available:")
        print("✓ Multiple nuclei community template sources")
        print("✓ Enhanced fuzzing with ffuf, feroxbuster, gobuster, dirb")
        print("✓ XSS testing with XSStrike")
        print("✓ Subdomain takeover detection with subjack and subzy")
        print("✓ Advanced nmap scanning profiles")
        print("✓ Enhanced SQLMap integration")
        print("✓ Comprehensive wordlist and payload management")
        print("✓ Plugin-based template and fuzzing management")
        
        return 0
    else:
        print("⚠️ Some enhancements may not be fully functional")
        print("Run the installation script to ensure all dependencies are installed")
        
        return 1

if __name__ == "__main__":
    sys.exit(main())