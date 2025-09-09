#!/usr/bin/env python3
"""
Security utilities and input sanitization for Bl4ckC3ll_PANTHEON
Provides secure input handling, validation, and sanitization functions
"""

import re
import html
import urllib.parse
from typing import List, Set, Dict, Any, Optional, Union
from pathlib import Path
import ipaddress
import socket
from urllib.parse import urlparse, quote, unquote


class InputSanitizer:
    """Comprehensive input sanitization and validation"""
    
    # Common dangerous patterns
    DANGEROUS_PATTERNS = {
        'path_traversal': re.compile(r'\.\.\/|\.\.\\|\.\.[\/\\]'),
        'command_injection': re.compile(r'[;&|`$\(\)]|\b(rm|del|format|shutdown)\b', re.IGNORECASE),
        'script_tags': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        'sql_injection': re.compile(r'(\b(union|select|insert|update|delete|drop|create|alter)\b|--|\'|"|\;)', re.IGNORECASE),
        'xss_patterns': re.compile(r'(javascript:|data:|vbscript:|onload|onerror|onclick)', re.IGNORECASE)
    }
    
    # Allowed characters for different input types
    ALLOWED_CHARS = {
        'domain': re.compile(r'^[a-zA-Z0-9.-]+$'),
        'url_path': re.compile(r'^[a-zA-Z0-9._/-]+$'),
        'filename': re.compile(r'^[a-zA-Z0-9._-]+$'),
        'alphanumeric': re.compile(r'^[a-zA-Z0-9]+$'),
        'parameter': re.compile(r'^[a-zA-Z0-9._-]+$')
    }
    
    @classmethod
    def sanitize_url(cls, url: str, max_length: int = 2048) -> Optional[str]:
        """
        Sanitize and validate URL input
        
        Args:
            url: URL to sanitize
            max_length: Maximum allowed URL length
            
        Returns:
            Sanitized URL or None if invalid
        """
        if not url or len(url) > max_length:
            return None
        
        # Remove any dangerous patterns
        for pattern_name, pattern in cls.DANGEROUS_PATTERNS.items():
            if pattern.search(url):
                return None
        
        try:
            # Parse and validate URL structure
            parsed = urlparse(url)
            
            # Check for valid scheme
            if parsed.scheme not in ('http', 'https'):
                return None
            
            # Check for valid netloc
            if not parsed.netloc or '..' in parsed.netloc:
                return None
            
            # Reconstruct URL safely
            sanitized = f"{parsed.scheme}://{parsed.netloc}"
            
            if parsed.path:
                # Sanitize path
                path_parts = [quote(part, safe='') for part in parsed.path.split('/')]
                sanitized += '/' + '/'.join(path_parts)
            
            if parsed.query:
                # Sanitize query parameters
                sanitized += '?' + quote(parsed.query, safe='&=')
            
            return sanitized
            
        except Exception:
            return None
    
    @classmethod
    def sanitize_domain(cls, domain: str) -> Optional[str]:
        """
        Sanitize domain name input
        
        Args:
            domain: Domain to sanitize
            
        Returns:
            Sanitized domain or None if invalid
        """
        if not domain or len(domain) > 255:
            return None
        
        # Remove whitespace and convert to lowercase
        domain = domain.strip().lower()
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS.values():
            if pattern.search(domain):
                return None
        
        # Validate domain format
        if not cls.ALLOWED_CHARS['domain'].match(domain):
            return None
        
        # Additional domain-specific validations
        if domain.startswith('.') or domain.endswith('.'):
            return None
        
        if '..' in domain:
            return None
        
        # Check if it's a valid domain format
        parts = domain.split('.')
        if len(parts) < 2:
            return None
        
        for part in parts:
            if not part or len(part) > 63:
                return None
            if part.startswith('-') or part.endswith('-'):
                return None
        
        return domain
    
    @classmethod
    def sanitize_filename(cls, filename: str, max_length: int = 255) -> Optional[str]:
        """
        Sanitize filename input
        
        Args:
            filename: Filename to sanitize
            max_length: Maximum filename length
            
        Returns:
            Sanitized filename or None if invalid
        """
        if not filename or len(filename) > max_length:
            return None
        
        # Remove path separators and dangerous characters
        filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '', filename)
        
        # Check for reserved Windows names
        reserved_names = {
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
            'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2',
            'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        }
        
        base_name = filename.split('.')[0].upper()
        if base_name in reserved_names:
            return None
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS.values():
            if pattern.search(filename):
                return None
        
        return filename.strip()
    
    @classmethod
    def sanitize_parameter(cls, param: str, max_length: int = 1000) -> Optional[str]:
        """
        Sanitize parameter input (query parameters, form data, etc.)
        
        Args:
            param: Parameter to sanitize
            max_length: Maximum parameter length
            
        Returns:
            Sanitized parameter or None if invalid
        """
        if not param or len(param) > max_length:
            return None
        
        # Check for dangerous patterns
        for pattern_name, pattern in cls.DANGEROUS_PATTERNS.items():
            if pattern.search(param):
                return None
        
        # HTML entity decode and re-encode safely
        try:
            decoded = html.unescape(param)
            # Re-encode dangerous characters
            encoded = html.escape(decoded, quote=True)
            return encoded
        except Exception:
            return None
    
    @classmethod
    def is_safe_path(cls, path: Union[str, Path]) -> bool:
        """
        Check if a file path is safe to use
        
        Args:
            path: Path to validate
            
        Returns:
            True if path is safe, False otherwise
        """
        path_str = str(path)
        
        # Check for path traversal
        if cls.DANGEROUS_PATTERNS['path_traversal'].search(path_str):
            return False
        
        # Check for dangerous directories (allow /home/user paths)
        dangerous_dirs = [
            '/etc/', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
            '/root/', '/var/', '/tmp/', '/proc/', '/sys/',
            'C:\\Windows\\', 'C:\\Program Files\\', 'C:\\Users\\'
        ]
        
        # Allow /home/user/ paths but not other system paths
        if path_str.startswith('/home/'):
            # Allow paths under /home/ but check for traversal
            if cls.DANGEROUS_PATTERNS['path_traversal'].search(path_str):
                return False
            return True
        
        for dangerous_dir in dangerous_dirs:
            if path_str.startswith(dangerous_dir):
                return False
        
        return True


class NetworkValidator:
    """Network-related validation and security checks"""
    
    # Private IP ranges (RFC 1918)
    PRIVATE_RANGES = [
        ipaddress.IPv4Network('10.0.0.0/8'),
        ipaddress.IPv4Network('172.16.0.0/12'),
        ipaddress.IPv4Network('192.168.0.0/16'),
        ipaddress.IPv4Network('127.0.0.0/8'),  # Loopback
    ]
    
    # Reserved/special use ranges
    RESERVED_RANGES = [
        ipaddress.IPv4Network('0.0.0.0/8'),     # "This" network
        ipaddress.IPv4Network('169.254.0.0/16'), # Link-local
        ipaddress.IPv4Network('224.0.0.0/4'),   # Multicast
        ipaddress.IPv4Network('240.0.0.0/4'),   # Reserved
    ]
    
    @classmethod
    def validate_target_host(cls, host: str) -> Dict[str, Any]:
        """
        Validate target host for security testing
        
        Args:
            host: Hostname or IP address to validate
            
        Returns:
            Validation result dictionary
        """
        result = {
            'valid': False,
            'type': None,
            'warnings': [],
            'errors': []
        }
        
        # Sanitize input
        sanitized_host = InputSanitizer.sanitize_domain(host)
        if not sanitized_host and not cls._is_valid_ip(host):
            result['errors'].append('Invalid host format')
            return result
        
        # Check if it's an IP address
        try:
            ip = ipaddress.IPv4Address(host)
            result['type'] = 'ip'
            result['ip_address'] = str(ip)
            
            # Check for private/reserved ranges
            if cls._is_private_ip(ip):
                result['warnings'].append('Target is in private IP range')
            elif cls._is_reserved_ip(ip):
                result['errors'].append('Target is in reserved IP range')
                return result
                
        except ipaddress.AddressValueError:
            # It's a domain name
            result['type'] = 'domain'
            result['domain'] = sanitized_host or host
            
            # Additional domain validation
            if not cls._validate_domain_name(result['domain']):
                result['errors'].append('Invalid domain name format')
                return result
        
        # Check for localhost/internal targets
        if cls._is_internal_target(host):
            result['warnings'].append('Target appears to be internal/localhost')
        
        result['valid'] = True
        return result
    
    @classmethod
    def _is_valid_ip(cls, ip_str: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except ipaddress.AddressValueError:
            try:
                ipaddress.IPv6Address(ip_str)
                return True
            except ipaddress.AddressValueError:
                return False
    
    @classmethod
    def _is_private_ip(cls, ip: ipaddress.IPv4Address) -> bool:
        """Check if IP is in private ranges"""
        return any(ip in network for network in cls.PRIVATE_RANGES)
    
    @classmethod
    def _is_reserved_ip(cls, ip: ipaddress.IPv4Address) -> bool:
        """Check if IP is in reserved ranges"""
        return any(ip in network for network in cls.RESERVED_RANGES)
    
    @classmethod
    def _validate_domain_name(cls, domain: str) -> bool:
        """Validate domain name format"""
        if not domain or len(domain) > 255:
            return False
        
        # Check each label
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        
        for label in labels:
            if not label or len(label) > 63:
                return False
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
                return False
        
        return True
    
    @classmethod
    def _is_internal_target(cls, host: str) -> bool:
        """Check if target is internal/localhost"""
        internal_indicators = [
            'localhost', '127.0.0.1', '::1',
            '.local', '.internal', '.corp',
            'test.', 'dev.', 'staging.'
        ]
        
        host_lower = host.lower()
        return any(indicator in host_lower for indicator in internal_indicators)


class SecureHeaders:
    """Security headers validation and recommendations"""
    
    SECURITY_HEADERS = {
        'strict-transport-security': {
            'required': True,
            'description': 'Enforces secure HTTPS connections'
        },
        'x-frame-options': {
            'required': True,
            'description': 'Prevents clickjacking attacks'
        },
        'x-content-type-options': {
            'required': True,
            'description': 'Prevents MIME-type sniffing'
        },
        'content-security-policy': {
            'required': True,
            'description': 'Prevents XSS and code injection'
        },
        'x-xss-protection': {
            'required': False,
            'description': 'Legacy XSS protection (deprecated)'
        },
        'referrer-policy': {
            'required': True,
            'description': 'Controls referrer information'
        }
    }
    
    @classmethod
    def analyze_headers(cls, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze HTTP headers for security issues
        
        Args:
            headers: Dictionary of HTTP headers
            
        Returns:
            Security analysis results
        """
        result = {
            'score': 0,
            'max_score': 0,
            'missing_headers': [],
            'present_headers': [],
            'recommendations': []
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header_name, config in cls.SECURITY_HEADERS.items():
            result['max_score'] += 1 if config['required'] else 0.5
            
            if header_name in headers_lower:
                result['present_headers'].append({
                    'name': header_name,
                    'value': headers_lower[header_name],
                    'description': config['description']
                })
                result['score'] += 1 if config['required'] else 0.5
            else:
                result['missing_headers'].append({
                    'name': header_name,
                    'required': config['required'],
                    'description': config['description']
                })
                
                if config['required']:
                    result['recommendations'].append(
                        f"Add {header_name} header: {config['description']}"
                    )
        
        # Calculate percentage score
        result['percentage'] = (result['score'] / result['max_score'] * 100) if result['max_score'] > 0 else 0
        
        return result


class RateLimiter:
    """Rate limiting for security testing to avoid overwhelming targets"""
    
    def __init__(self, requests_per_second: float = 10.0, burst_limit: int = 50):
        """
        Initialize rate limiter
        
        Args:
            requests_per_second: Maximum requests per second
            burst_limit: Maximum burst requests allowed
        """
        import time
        import collections
        
        self.rate = requests_per_second
        self.burst_limit = burst_limit
        self.tokens = float(burst_limit)
        self.last_update = time.time()
        self.request_times = collections.deque(maxlen=1000)
    
    def acquire(self, tokens: int = 1) -> bool:
        """
        Acquire tokens from rate limiter
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            True if tokens acquired, False if rate limited
        """
        import time
        
        now = time.time()
        
        # Add tokens based on elapsed time
        elapsed = now - self.last_update
        self.tokens = min(self.burst_limit, self.tokens + elapsed * self.rate)
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            self.request_times.append(now)
            return True
        
        return False
    
    def wait_time(self) -> float:
        """
        Calculate wait time before next request can be made
        
        Returns:
            Wait time in seconds
        """
        if self.tokens >= 1:
            return 0.0
        
        return (1 - self.tokens) / self.rate
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get rate limiter statistics
        
        Returns:
            Statistics dictionary
        """
        import time
        
        now = time.time()
        recent_requests = sum(1 for t in self.request_times if now - t <= 60)
        
        return {
            'current_tokens': self.tokens,
            'max_tokens': self.burst_limit,
            'rate_per_second': self.rate,
            'requests_last_minute': recent_requests,
            'next_token_in': max(0, self.wait_time())
        }


def create_security_context(operation: str, target: str) -> Dict[str, Any]:
    """
    Create security context for logging and auditing
    
    Args:
        operation: Security operation being performed
        target: Target being tested
        
    Returns:
        Security context dictionary
    """
    import datetime
    import getpass
    import socket
    
    # Validate inputs
    operation = InputSanitizer.sanitize_parameter(operation) or "unknown"
    target = InputSanitizer.sanitize_domain(target) or "unknown"
    
    context = {
        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'operation': operation,
        'target': target,
        'user': getpass.getuser(),
        'hostname': socket.gethostname(),
        'authorized': False,  # Must be explicitly set to True
        'scope': 'unknown'
    }
    
    return context