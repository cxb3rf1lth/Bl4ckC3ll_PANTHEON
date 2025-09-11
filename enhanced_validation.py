#!/usr/bin/env python3
"""
Enhanced Validation and Error Handling Module for Bl4ckC3ll_PANTHEON
Provides comprehensive validation, error recovery, and performance monitoring
"""

import re
import time
import threading
import functools
import traceback
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Union
from datetime import datetime, timezone
import json
import hashlib


class EnhancedValidator:
    """Advanced input validation with security and performance considerations"""
    
    def __init__(self):
        self.validation_cache = {}
        self.cache_lock = threading.Lock()
        
    def validate_domain(self, domain: str) -> bool:
        """Validate domain name with comprehensive checks"""
        if not domain or not isinstance(domain, str):
            return False
        
        # First check if it's an IP address - if so, it's not a valid domain
        if self.validate_ip_address(domain):
            return False
            
        # Basic format validation
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        if not re.match(domain_pattern, domain):
            return False
            
        # Length checks
        if len(domain) > 253 or len(domain) < 1:
            return False
            
        # Check each label
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63 or len(label) < 1:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
                
        return True
    
    def validate_url(self, url: str) -> bool:
        """Validate URL with security considerations"""
        if not url or not isinstance(url, str):
            return False
            
        # Check for dangerous protocols
        dangerous_protocols = ['file://', 'ftp://', 'ldap://', 'dict://', 'gopher://']
        url_lower = url.lower()
        
        for protocol in dangerous_protocols:
            if url_lower.startswith(protocol):
                return False
                
        # Basic URL pattern validation
        url_pattern = r'^https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?::\d{1,5})?(?:/[^\s]*)?$'
        return re.match(url_pattern, url) is not None
    
    def validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format"""
        if not ip or not isinstance(ip, str):
            return False
            
        # IPv4 validation
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ipv4_pattern, ip):
            return True
            
        # IPv6 validation (basic)
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        return re.match(ipv6_pattern, ip) is not None
    
    def validate_file_path(self, path: str, allowed_extensions: List[str] = None) -> bool:
        """Validate file path with security checks"""
        if not path or not isinstance(path, str):
            return False
            
        # Check for path traversal attempts
        if '..' in path or path.startswith('/'):
            return False
            
        # Validate extension if specified
        if allowed_extensions:
            path_obj = Path(path)
            if path_obj.suffix.lower() not in allowed_extensions:
                return False
                
        # Check for dangerous filenames
        dangerous_names = ['con', 'prn', 'aux', 'nul'] + [f'com{i}' for i in range(10)] + [f'lpt{i}' for i in range(10)]
        filename = Path(path).stem.lower()
        if filename in dangerous_names:
            return False
            
        return True
    
    def validate_with_cache(self, value: str, validator_func: Callable, cache_key: str = None) -> bool:
        """Validate with caching for performance"""
        if not cache_key:
            # SECURITY FIX: Use SHA-256 instead of MD5
            cache_key = hashlib.sha256(f"{validator_func.__name__}:{value}".encode()).hexdigest()
            
        with self.cache_lock:
            if cache_key in self.validation_cache:
                return self.validation_cache[cache_key]
                
            result = validator_func(value)
            self.validation_cache[cache_key] = result
            
            # Limit cache size
            if len(self.validation_cache) > 1000:
                # Remove oldest entries
                keys_to_remove = list(self.validation_cache.keys())[:100]
                for key in keys_to_remove:
                    del self.validation_cache[key]
                    
            return result


class PerformanceMonitor:
    """Performance monitoring and optimization utilities"""
    
    def __init__(self):
        self.metrics = {}
        self.metrics_lock = threading.Lock()
        
    def time_function(self, func_name: str = None):
        """Decorator to monitor function execution time"""
        def decorator(func):
            name = func_name or f"{func.__module__}.{func.__name__}"
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    execution_time = time.time() - start_time
                    self._record_metric(name, execution_time, "success")
                    return result
                except Exception as e:
                    execution_time = time.time() - start_time
                    self._record_metric(name, execution_time, "error")
                    raise
            return wrapper
        return decorator
    
    def _record_metric(self, func_name: str, execution_time: float, status: str):
        """Record performance metric"""
        with self.metrics_lock:
            if func_name not in self.metrics:
                self.metrics[func_name] = {
                    'total_calls': 0,
                    'total_time': 0,
                    'min_time': float('inf'),
                    'max_time': 0,
                    'errors': 0,
                    'successes': 0
                }
                
            metric = self.metrics[func_name]
            metric['total_calls'] += 1
            metric['total_time'] += execution_time
            metric['min_time'] = min(metric['min_time'], execution_time)
            metric['max_time'] = max(metric['max_time'], execution_time)
            
            if status == "error":
                metric['errors'] += 1
            else:
                metric['successes'] += 1
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        with self.metrics_lock:
            report = {}
            for func_name, metric in self.metrics.items():
                if metric['total_calls'] > 0:
                    report[func_name] = {
                        'total_calls': metric['total_calls'],
                        'average_time': metric['total_time'] / metric['total_calls'],
                        'min_time': metric['min_time'],
                        'max_time': metric['max_time'],
                        'success_rate': metric['successes'] / metric['total_calls'],
                        'error_rate': metric['errors'] / metric['total_calls']
                    }
            return report
    
    def get_slow_functions(self, threshold: float = 1.0) -> List[str]:
        """Get list of functions that are slower than threshold"""
        slow_functions = []
        report = self.get_performance_report()
        
        for func_name, metrics in report.items():
            if metrics['average_time'] > threshold:
                slow_functions.append(func_name)
                
        return slow_functions


class EnhancedErrorRecovery:
    """Advanced error recovery and resilience mechanisms"""
    
    def __init__(self):
        self.retry_config = {
            'max_retries': 3,
            'backoff_factor': 2,
            'initial_delay': 1
        }
        self.circuit_breakers = {}
        
    def retry_with_backoff(self, max_retries: int = None, backoff_factor: float = None):
        """Decorator for retry with exponential backoff"""
        max_retries = max_retries or self.retry_config['max_retries']
        backoff_factor = backoff_factor or self.retry_config['backoff_factor']
        
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                last_exception = None
                delay = self.retry_config['initial_delay']
                
                for attempt in range(max_retries + 1):
                    try:
                        return func(*args, **kwargs)
                    except KeyboardInterrupt:
                        # Don't retry on user interruption
                        raise
                    except Exception as e:
                        last_exception = e
                        
                        if attempt < max_retries:
                            time.sleep(delay)
                            delay *= backoff_factor
                        else:
                            break
                            
                # If all retries failed, raise the last exception
                raise last_exception
            return wrapper
        return decorator
    
    def circuit_breaker(self, failure_threshold: int = 5, recovery_timeout: float = 60):
        """Circuit breaker pattern implementation"""
        def decorator(func):
            func_name = f"{func.__module__}.{func.__name__}"
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                breaker = self._get_circuit_breaker(func_name, failure_threshold, recovery_timeout)
                
                if breaker['state'] == 'open':
                    if time.time() - breaker['last_failure'] > recovery_timeout:
                        breaker['state'] = 'half-open'
                    else:
                        raise Exception(f"Circuit breaker open for {func_name}")
                
                try:
                    result = func(*args, **kwargs)
                    
                    if breaker['state'] == 'half-open':
                        breaker['state'] = 'closed'
                        breaker['failure_count'] = 0
                        
                    return result
                    
                except Exception as e:
                    breaker['failure_count'] += 1
                    breaker['last_failure'] = time.time()
                    
                    if breaker['failure_count'] >= failure_threshold:
                        breaker['state'] = 'open'
                        
                    raise
                    
            return wrapper
        return decorator
    
    def _get_circuit_breaker(self, func_name: str, failure_threshold: int, recovery_timeout: float) -> Dict[str, Any]:
        """Get or create circuit breaker state"""
        if func_name not in self.circuit_breakers:
            self.circuit_breakers[func_name] = {
                'state': 'closed',  # closed, open, half-open
                'failure_count': 0,
                'last_failure': 0,
                'failure_threshold': failure_threshold,
                'recovery_timeout': recovery_timeout
            }
        return self.circuit_breakers[func_name]


class SecurityValidator:
    """Enhanced security validation and sanitization"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',  # XSS
            r'(\b(union|select|insert|delete|update|drop|create|alter)\b)',  # SQL injection
            r'(\.\./){2,}',  # Path traversal
            r'(eval|exec|system|shell_exec|passthru)\s*\(',  # Code injection
        ]
        
    def sanitize_input(self, value: str, max_length: int = 1000) -> str:
        """Sanitize input with comprehensive cleaning"""
        if not isinstance(value, str):
            return str(value)
            
        # Trim to max length
        value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Remove control characters except whitespace
        value = ''.join(char for char in value if ord(char) >= 32 or char.isspace())
        
        # Basic HTML entity encoding for dangerous characters
        value = value.replace('&', '&amp;')
        value = value.replace('<', '&lt;')
        value = value.replace('>', '&gt;')
        value = value.replace('"', '&quot;')
        value = value.replace("'", '&#x27;')
        
        return value
    
    def is_suspicious_input(self, value: str) -> bool:
        """Check if input contains suspicious patterns"""
        if not isinstance(value, str):
            return False
            
        value_lower = value.lower()
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                return True
                
        return False
    
    def validate_command_args(self, args: List[str]) -> bool:
        """Validate command line arguments for safety"""
        if not isinstance(args, list):
            return False
            
        dangerous_chars = ['|', '&', ';', '$(', '`', '>', '<', '*', '?']
        
        for arg in args:
            if not isinstance(arg, str):
                continue
                
            # Check for dangerous characters
            for char in dangerous_chars:
                if char in arg:
                    return False
                    
            # Check for suspicious patterns
            if self.is_suspicious_input(arg):
                return False
                
        return True


class EnhancedConfigValidator:
    """Advanced configuration validation with schema support"""
    
    def __init__(self):
        self.validator = EnhancedValidator()
        self.security = SecurityValidator()
        
    def validate_scan_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate scanning configuration with enhanced checks"""
        validated_config = config.copy()
        
        # Validate limits section
        limits = validated_config.get('limits', {})
        limits['parallel_jobs'] = self._validate_range(limits.get('parallel_jobs', 10), 1, 50)
        limits['http_timeout'] = self._validate_range(limits.get('http_timeout', 30), 5, 300)
        limits['rps'] = self._validate_range(limits.get('rps', 500), 1, 5000)
        limits['max_concurrent_scans'] = self._validate_range(limits.get('max_concurrent_scans', 8), 1, 20)
        validated_config['limits'] = limits
        
        # Validate nuclei section
        nuclei = validated_config.get('nuclei', {})
        nuclei['rps'] = self._validate_range(nuclei.get('rps', 800), 1, 5000)
        nuclei['conc'] = self._validate_range(nuclei.get('conc', 150), 1, 1000)
        nuclei['timeout'] = self._validate_range(nuclei.get('timeout', 10), 5, 300)
        
        # Validate severity levels
        allowed_severities = ['info', 'low', 'medium', 'high', 'critical']
        severity = nuclei.get('severity', 'medium,high,critical')
        if isinstance(severity, str):
            severity_list = [s.strip().lower() for s in severity.split(',')]
            valid_severities = [s for s in severity_list if s in allowed_severities]
            nuclei['severity'] = ','.join(valid_severities) if valid_severities else 'medium,high,critical'
            
        validated_config['nuclei'] = nuclei
        
        # Validate repository URLs
        repos = validated_config.get('repos', {})
        validated_repos = {}
        
        for name, url in repos.items():
            if isinstance(url, str) and self.validator.validate_url(url):
                validated_repos[name] = url
                
        validated_config['repos'] = validated_repos
        
        return validated_config
    
    def _validate_range(self, value: Any, min_val: int, max_val: int, default: int = None) -> int:
        """Validate numeric value within range"""
        try:
            num_val = int(value)
            return max(min_val, min(num_val, max_val))
        except (ValueError, TypeError):
            return default or min_val


# Global instances for easy access
enhanced_validator = EnhancedValidator()
performance_monitor = PerformanceMonitor()
error_recovery = EnhancedErrorRecovery()
security_validator = SecurityValidator()
config_validator = EnhancedConfigValidator()


def enhanced_safe_execute(func: Callable, *args, **kwargs) -> Any:
    """Enhanced safe execution with comprehensive error handling"""
    @error_recovery.retry_with_backoff(max_retries=2)
    @performance_monitor.time_function()
    def _execute():
        return func(*args, **kwargs)
    
    try:
        return _execute()
    except Exception as e:
        # Log the error with full context
        error_info = {
            'function': f"{func.__module__}.{func.__name__}" if hasattr(func, '__module__') else str(func),
            'error': str(e),
            'traceback': traceback.format_exc(),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Could log to file or monitoring system here
        print(f"Enhanced safe execute error: {error_info}")
        return None


if __name__ == "__main__":
    # Example usage and testing
    validator = EnhancedValidator()
    
    # Test domain validation
    print("Domain validation tests:")
    print(f"example.com: {validator.validate_domain('example.com')}")
    print(f"invalid..domain: {validator.validate_domain('invalid..domain')}")
    
    # Test URL validation  
    print("\nURL validation tests:")
    print(f"https://example.com: {validator.validate_url('https://example.com')}")
    print(f"file:///etc/passwd: {validator.validate_url('file:///etc/passwd')}")
    
    # Test performance monitoring
    @performance_monitor.time_function()
    def test_function():
        time.sleep(0.1)
        return "test result"
    
    test_function()
    test_function()
    
    print("\nPerformance report:")
    report = performance_monitor.get_performance_report()
    for func, metrics in report.items():
        print(f"{func}: avg={metrics['average_time']:.3f}s, calls={metrics['total_calls']}")