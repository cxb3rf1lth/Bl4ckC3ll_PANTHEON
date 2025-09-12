#!/usr/bin/env python3
"""
Security Enhancements for Bl4ckC3ll_PANTHEON
Comprehensive security improvements and hardening measures
"""

import os
import sys
import re
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import json


def setup_comprehensive_logging():
    """Setup comprehensive logging configuration"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "security_enhancements.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Configure security logger
    security_logger = logging.getLogger('security')
    security_handler = logging.FileHandler(log_dir / "security.log")
    security_handler.setFormatter(
        logging.Formatter('%(asctime)s - SECURITY - %(levelname)s - %(message)s')
    )
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    
    logging.info("Comprehensive logging configured")


def add_input_validation_checks():
    """Add comprehensive input validation checks to existing functions"""
    
    validation_code = '''
# Enhanced input validation for security
def validate_command_args(args: List[str]) -> bool:
    """Validate command arguments for security"""
    if not isinstance(args, list):
        return False
    
    dangerous_patterns = [
        r'[;&|`$()]',  # Command injection
        r'\.\./|\.\.\\\\',  # Path traversal
        r'<script|javascript:|data:',  # XSS
        r'union\s+select|drop\s+table',  # SQL injection
        r'(rm|del|format)\s+',  # Destructive commands
    ]
    
    for arg in args:
        if not isinstance(arg, str):
            continue
        if len(arg) > 1000:  # Prevent buffer overflow
            return False
        for pattern in dangerous_patterns:
            if re.search(pattern, arg, re.IGNORECASE):
                logging.getLogger('security').warning(f"Dangerous pattern detected: {pattern} in {arg[:50]}")
                return False
    
    return True


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for security"""
    if not isinstance(filename, str):
        return "invalid_filename"
    
    # Remove path traversal attempts
    filename = re.sub(r'\.\.[\\/]', '', filename)
    
    # Remove special characters
    filename = re.sub(r'[<>:"|?*]', '_', filename)
    
    # Limit length
    filename = filename[:255]
    
    # Ensure not empty
    if not filename.strip():
        filename = "unnamed_file"
    
    return filename


def validate_network_address(address: str) -> bool:
    """Validate network address for security"""
    if not isinstance(address, str) or len(address) > 253:
        return False
    
    # Block private/localhost addresses in production
    blocked_patterns = [
        r'^127\.',  # Localhost
        r'^192\.168\.',  # Private
        r'^10\.',  # Private
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',  # Private
        r'^169\.254\.',  # Link-local
        r'^0\.',  # Invalid
    ]
    
    for pattern in blocked_patterns:
        if re.match(pattern, address):
            logging.getLogger('security').warning(f"Blocked private/localhost address: {address}")
            return False
    
    return True
'''
    
    # Add validation to main script
    main_script = Path("bl4ckc3ll_p4nth30n.py")
    if main_script.exists():
        with open(main_script, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find a good place to insert validation functions
        insert_point = content.find("def validate_domain_input")
        if insert_point != -1:
            # Insert before validate_domain_input
            content = content[:insert_point] + validation_code + "\n\n" + content[insert_point:]
            
            with open(main_script, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logging.info("Added enhanced input validation to main script")
        else:
            logging.warning("Could not find insertion point for validation code")


def enhance_subprocess_security():
    """Enhance subprocess security throughout the codebase"""
    
    security_improvements = {
        # Replace shell=True with safer alternatives
        r'subprocess\.run\([^,]+,\s*shell=True': r'subprocess.run(shlex.split(\1, timeout=300), shell=False',
        r'subprocess\.Popen\([^,]+,\s*shell=True': r'subprocess.Popen(shlex.split(\1), shell=False',
        
        # Add timeout to subprocess calls without one
        r'subprocess\.run\(([^)]+)\)': r'subprocess.run(\1, timeout=300, timeout=300)',
    }
    
    python_files = list(Path(".").glob("*.py"))
    
    for file_path in python_files:
        if not file_path.exists():
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Apply security improvements
            for pattern, replacement in security_improvements.items():
                if re.search(pattern, content):
                    content = re.sub(pattern, replacement, content)
                    logging.info(f"Applied subprocess security fix in {file_path}")
            
            # Only write if changes were made
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")


def create_security_config():
    """Create comprehensive security configuration"""
    
    security_config = {
        "security": {
            "input_validation": {
                "max_string_length": 1000,
                "max_list_size": 100,
                "blocked_patterns": [
                    r'[;&|`$()]',
                    r'\.\./|\.\.\\\\',
                    r'<script|javascript:|data:',
                    r'union\s+select|drop\s+table'
                ]
            },
            "network": {
                "allow_private_addresses": False,
                "max_connections": 50,
                "timeout_seconds": 30,
                "rate_limit_requests_per_minute": 60
            },
            "file_operations": {
                "allowed_extensions": [".txt", ".json", ".html", ".xml", ".csv"],
                "max_file_size_mb": 100,
                "quarantine_suspicious_files": True
            },
            "subprocess": {
                "default_timeout": 300,
                "allowed_commands": [
                    "nmap", "nuclei", "subfinder", "httpx", "ffuf", 
                    "sqlmap", "nikto", "dirb", "gobuster", "amass"
                ],
                "block_shell_execution": True
            },
            "logging": {
                "log_level": "INFO",
                "log_security_events": True,
                "log_file_operations": True,
                "log_network_requests": True
            }
        }
    }
    
    config_file = Path("security_config.json")
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(security_config, f, indent=2)
    
    logging.info(f"Security configuration created: {config_file}")


def add_rate_limiting():
    """Add rate limiting functionality"""
    
    rate_limiting_code = '''
# Rate limiting for security
import time
from collections import defaultdict
from threading import Lock

class RateLimiter:
    """Thread-safe rate limiter for security"""
    
    def __init__(self, max_requests: int = 60, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(list)
        self.lock = Lock()
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed under rate limit"""
        current_time = time.time()
        
        with self.lock:
            # Clean old requests
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if current_time - req_time < self.time_window
            ]
            
            # Check if under limit
            if len(self.requests[identifier]) < self.max_requests:
                self.requests[identifier].append(current_time)
                return True
            
            return False
    
    def wait_time(self, identifier: str) -> float:
        """Get wait time until next request is allowed"""
        current_time = time.time()
        
        with self.lock:
            if not self.requests[identifier]:
                return 0.0
            
            oldest_request = min(self.requests[identifier])
            wait_time = self.time_window - (current_time - oldest_request)
            return max(0.0, wait_time)

# Global rate limiter instance
rate_limiter = RateLimiter()
'''
    
    main_script = Path("bl4ckc3ll_p4nth30n.py")
    if main_script.exists():
        with open(main_script, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Add rate limiting after imports
        import_end = content.find("# SECURITY: Input validation imports")
        if import_end != -1:
            content = content[:import_end] + rate_limiting_code + "\n\n" + content[import_end:]
            
            with open(main_script, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logging.info("Added rate limiting functionality")


def improve_error_handling():
    """Improve error handling throughout the codebase"""
    
    # Find and improve generic exception handlers
    python_files = list(Path(".").glob("*.py"))
    
    improvements_made = 0
    
    for file_path in python_files:
        if not file_path.exists():
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Improve generic exception handling
            patterns = [
                (r'except Exception:\s*\n\s*pass', 
                 'except Exception as e:\n                logging.warning(f"Operation failed: {e}")'),
                (r'except:\s*\n\s*pass', 
                 'except Exception as e:\n                logging.warning(f"Unexpected error: {e}")'),
            ]
            
            for pattern, replacement in patterns:
                if re.search(pattern, content):
                    content = re.sub(pattern, replacement, content)
                    improvements_made += 1
            
            # Only write if changes were made
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
        except Exception as e:
            logging.error(f"Error improving error handling in {file_path}: {e}")
    
    logging.info(f"Improved error handling in {improvements_made} locations")


def create_security_monitoring():
    """Create security monitoring and alerting"""
    
    monitoring_script = '''#!/usr/bin/env python3
"""
Security Monitoring for Bl4ckC3ll_PANTHEON
Real-time security event monitoring and alerting
"""

import logging
import time
import re
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SecurityMonitor(FileSystemEventHandler):
    """Monitor for security events"""
    
    def __init__(self):
        self.security_logger = logging.getLogger('security')
        self.suspicious_patterns = [
            r'failed login',
            r'unauthorized access',
            r'injection attempt',
            r'path traversal',
            r'rate limit exceeded'
        ]
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        if event.src_path.endswith('.log'):
            self.check_log_file(event.src_path)
    
    def check_log_file(self, log_path):
        """Check log file for suspicious activity"""
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                # Read only new lines (simplified approach)
                lines = f.readlines()[-10:]  # Last 10 lines
                
                for line in lines:
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            self.security_logger.warning(f"Suspicious activity detected: {line.strip()}")
                            
        except Exception as e:
            self.security_logger.error(f"Error checking log file {log_path}: {e}")

def start_monitoring():
    """Start security monitoring"""
    monitor = SecurityMonitor()
    observer = Observer()
    observer.schedule(monitor, 'logs', recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()

if __name__ == "__main__":
    start_monitoring()
'''
    
    monitor_file = Path("security_monitor.py")
    with open(monitor_file, 'w', encoding='utf-8') as f:
        f.write(monitoring_script)
    
    # Make executable
    monitor_file.chmod(0o755)
    
    logging.info(f"Security monitoring script created: {monitor_file}")


def main():
    """Main security enhancement function"""
    print("🔒 Starting Comprehensive Security Enhancements...")
    
    setup_comprehensive_logging()
    
    enhancements = [
        ("Setting up comprehensive logging", setup_comprehensive_logging),
        ("Adding input validation checks", add_input_validation_checks),
        ("Enhancing subprocess security", enhance_subprocess_security),
        ("Creating security configuration", create_security_config),
        ("Adding rate limiting", add_rate_limiting),
        ("Improving error handling", improve_error_handling),
        ("Creating security monitoring", create_security_monitoring),
    ]
    
    completed = 0
    for description, func in enhancements:
        try:
            print(f"🔧 {description}...")
            func()
            completed += 1
            print(f"✅ {description} completed")
        except Exception as e:
            print(f"❌ {description} failed: {e}")
            logging.error(f"Enhancement failed: {description} - {e}")
    
    print(f"\n🎉 Security Enhancements Complete: {completed}/{len(enhancements)} successful")
    
    if completed == len(enhancements):
        print("✅ All security enhancements applied successfully!")
    else:
        print("⚠️ Some enhancements failed - check logs for details")


if __name__ == "__main__":
    main()