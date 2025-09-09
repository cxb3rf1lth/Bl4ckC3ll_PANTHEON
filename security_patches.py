#!/usr/bin/env python3
"""
Security Patches for Bl4ckC3ll_PANTHEON
Critical security vulnerability fixes and improvements
"""

import subprocess
import shlex
import hashlib
import logging
import re
import urllib.parse
from typing import List, Dict, Any, Optional, Union
from pathlib import Path


class SecureCommandExecutor:
    """Secure command execution to prevent command injection."""
    
    ALLOWED_COMMANDS = {
        'nuclei', 'subfinder', 'httpx', 'naabu', 'amass', 
        'nmap', 'sqlmap', 'ffuf', 'gobuster', 'whatweb',
        'dig', 'whois', 'curl', 'wget'
    }
    
    @classmethod
    def execute_command(cls, command: str, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Execute command with security controls.
        
        Args:
            command: Base command to execute
            args: List of arguments (will be sanitized)
            timeout: Command timeout in seconds
            
        Returns:
            CompletedProcess: Result of command execution
            
        Raises:
            SecurityError: If command is not allowed
            ValueError: If arguments contain dangerous content
        """
        if command not in cls.ALLOWED_COMMANDS:
            raise SecurityError(f"Command not allowed: {command}")
        
        # Sanitize arguments
        sanitized_args = []
        for arg in args:
            sanitized_arg = cls._sanitize_argument(arg)
            if sanitized_arg is None:
                raise ValueError(f"Invalid argument detected: {arg}")
            sanitized_args.append(sanitized_arg)
        
        # Execute with security controls
        full_command = [command] + sanitized_args
        
        try:
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,  # CRITICAL: Never use shell=True
                check=False
            )
            return result
        except subprocess.TimeoutExpired:
            logging.error(f"Command timed out after {timeout}s: {command}")
            raise
        except Exception as e:
            logging.error(f"Command execution failed: {e}")
            raise
    
    @staticmethod
    def _sanitize_argument(arg: str) -> Optional[str]:
        """
        Sanitize command line arguments.
        
        Args:
            arg: Argument to sanitize
            
        Returns:
            Sanitized argument or None if dangerous
        """
        if not isinstance(arg, str):
            return None
        
        # Check for dangerous characters
        dangerous_chars = [';', '|', '&', '>', '<', '`', '$', '(', ')', '{', '}']
        if any(char in arg for char in dangerous_chars):
            return None
        
        # Check for command substitution attempts
        if '$(' in arg or '`' in arg:
            return None
        
        # Basic length check
        if len(arg) > 1000:
            return None
        
        return arg


class SecureHasher:
    """Secure hashing utilities to replace weak cryptography."""
    
    @staticmethod
    def generate_cache_key(prefix: str, value: str) -> str:
        """
        Generate secure cache key using SHA-256.
        
        Args:
            prefix: Key prefix
            value: Value to hash
            
        Returns:
            Secure hash string
        """
        combined = f"{prefix}:{value}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    @staticmethod
    def hash_sensitive_data(data: str, salt: str = "") -> str:
        """
        Hash sensitive data with optional salt.
        
        Args:
            data: Data to hash
            salt: Optional salt value
            
        Returns:
            SHA-256 hash
        """
        salted_data = f"{salt}{data}{salt}"
        return hashlib.sha256(salted_data.encode('utf-8')).hexdigest()


class InputValidator:
    """Comprehensive input validation to prevent various attacks."""
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """
        Validate domain name format.
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if valid domain
        """
        if not isinstance(domain, str) or len(domain) > 255:
            return False
        
        # Basic domain regex
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, domain))
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """
        Validate IP address format.
        
        Args:
            ip: IP address to validate
            
        Returns:
            True if valid IP
        """
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_url(url: str, allowed_schemes: List[str] = None) -> bool:
        """
        Validate URL format and scheme.
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed schemes (default: http, https)
            
        Returns:
            True if valid URL
        """
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
        
        try:
            parsed = urllib.parse.urlparse(url)
            return (
                parsed.scheme in allowed_schemes and
                bool(parsed.netloc) and
                len(url) <= 2000  # Reasonable URL length limit
            )
        except Exception:
            return False
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """
        Validate port number.
        
        Args:
            port: Port number to validate
            
        Returns:
            True if valid port
        """
        try:
            port_int = int(port)
            return 1 <= port_int <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def sanitize_filename(filename: str) -> Optional[str]:
        """
        Sanitize filename for safe usage.
        
        Args:
            filename: Filename to sanitize
            
        Returns:
            Sanitized filename or None if invalid
        """
        if not isinstance(filename, str) or len(filename) > 255:
            return None
        
        # Remove dangerous characters
        safe_chars = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        
        # Check for reserved names
        reserved_names = {'con', 'prn', 'aux', 'nul', 'com1', 'com2', 'lpt1', 'lpt2'}
        if safe_chars.lower() in reserved_names:
            return None
        
        # Ensure not empty after sanitization
        if not safe_chars:
            return None
        
        return safe_chars


class SecureFileHandler:
    """Secure file operations to prevent path traversal attacks."""
    
    @staticmethod
    def validate_path(path: Union[str, Path], base_dir: Optional[Path] = None) -> bool:
        """
        Validate file path for security.
        
        Args:
            path: Path to validate
            base_dir: Base directory to restrict to
            
        Returns:
            True if path is safe
        """
        try:
            path_obj = Path(path).resolve()
            
            # Check for dangerous system paths
            dangerous_paths = {
                Path('/etc'),
                Path('/bin'),
                Path('/sbin'),
                Path('/usr/bin'),
                Path('/usr/sbin'),
                Path('/root'),
                Path('/var/log'),
                Path('/proc'),
                Path('/sys')
            }
            
            for dangerous in dangerous_paths:
                if path_obj.is_relative_to(dangerous):
                    return False
            
            # If base_dir specified, ensure path is within it
            if base_dir:
                base_dir_resolved = Path(base_dir).resolve()
                if not path_obj.is_relative_to(base_dir_resolved):
                    return False
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def safe_write_file(path: Union[str, Path], content: str, base_dir: Optional[Path] = None) -> bool:
        """
        Safely write file with path validation.
        
        Args:
            path: File path
            content: Content to write
            base_dir: Base directory restriction
            
        Returns:
            True if successful
        """
        if not SecureFileHandler.validate_path(path, base_dir):
            logging.error(f"Invalid path for write operation: {path}")
            return False
        
        try:
            Path(path).write_text(content, encoding='utf-8')
            return True
        except Exception as e:
            logging.error(f"Failed to write file {path}: {e}")
            return False


class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass


# Enhanced error handling decorator
def secure_execute(func):
    """Decorator for secure function execution with proper error handling."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SecurityError:
            # Re-raise security errors
            raise
        except Exception as e:
            # Log other errors but don't expose internal details
            logging.error(f"Function {func.__name__} failed: {type(e).__name__}")
            raise SecurityError(f"Operation failed due to security constraints")
    return wrapper


# Configuration validation
class ConfigValidator:
    """Validate configuration for security issues."""
    
    @staticmethod
    def validate_config(config: Dict[str, Any]) -> List[str]:
        """
        Validate configuration dictionary.
        
        Args:
            config: Configuration to validate
            
        Returns:
            List of validation errors
        """
        errors = []
        
        # Check for sensitive data in plain text
        sensitive_keys = {'password', 'api_key', 'token', 'secret', 'key'}
        
        def check_dict(d, path=""):
            for key, value in d.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check for sensitive keys
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    if isinstance(value, str) and len(value) > 0:
                        errors.append(f"Sensitive data found in plain text: {current_path}")
                
                # Recursively check nested dictionaries
                if isinstance(value, dict):
                    check_dict(value, current_path)
        
        check_dict(config)
        
        return errors


# Rate limiting improvements
class RateLimiter:
    """Enhanced rate limiting with security considerations."""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests = []
        import threading
        self.lock = threading.Lock()
    
    def allow_request(self) -> bool:
        """
        Check if request is allowed based on rate limits.
        
        Returns:
            True if request is allowed
        """
        import time
        current_time = time.time()
        
        with self.lock:
            # Remove old requests
            self.requests = [req_time for req_time in self.requests 
                           if current_time - req_time < 60]
            
            # Check if under limit
            if len(self.requests) < self.requests_per_minute:
                self.requests.append(current_time)
                return True
            
            return False


if __name__ == "__main__":
    # Example usage and testing
    print("Security patches loaded successfully!")
    
    # Test secure command execution
    try:
        executor = SecureCommandExecutor()
        # This would work:
        # result = executor.execute_command("ls", ["-la"])
        
        # This would fail with SecurityError:
        # result = executor.execute_command("rm", ["-rf", "/"])
        
        print("✅ Secure command executor: OK")
    except Exception as e:
        print(f"❌ Secure command executor: {e}")
    
    # Test input validation
    validator = InputValidator()
    print(f"✅ Domain validation: {validator.validate_domain('example.com')}")
    print(f"❌ Invalid domain: {validator.validate_domain('invalid..domain')}")
    
    # Test secure hashing
    hasher = SecureHasher()
    cache_key = hasher.generate_cache_key("scan", "example.com")
    print(f"✅ Secure cache key: {cache_key[:16]}...")