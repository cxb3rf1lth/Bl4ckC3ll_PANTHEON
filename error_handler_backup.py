#!/usr/bin/env python3
"""
Enhanced error handling and logging utilities for Bl4ckC3ll_PANTHEON
Advanced backup version with extended functionality
"""

import sys
import os
import traceback
import functools
import logging
import re
from pathlib import Path
from typing import Any, Callable, Dict, Optional, TypeVar, Union
from datetime import datetime
import json

# Type variable for decorated functions
F = TypeVar('F', bound=Callable[..., Any])


class SecurityTestingError(Exception):
    """Base exception for security testing operations"""
    pass


class ConfigurationError(SecurityTestingError):
    """Raised when configuration validation fails"""
    pass


class ToolExecutionError(SecurityTestingError):
    """Raised when tool execution fails"""
    def __init__(self, tool: str, return_code: int, stderr: str = ""):
        self.tool = tool
        self.return_code = return_code
        self.stderr = stderr
        super().__init__(f"Tool '{tool}' failed with return code {return_code}: {stderr}")


class NetworkError(SecurityTestingError):
    """Raised when network operations fail"""
    pass


class ValidationError(SecurityTestingError):
    """Raised when input validation fails"""
    pass


class EnhancedLogger:
    """Enhanced logger with structured logging and error context"""
    
    def __init__(self, name: str = "bl4ckc3ll_pantheon", log_dir: Path = None):
        self.name = name
        self.log_dir = log_dir or Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        
        # Set up logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # File handler
        log_file = self.log_dir / f"{name}.log"
        self.log_file = log_file
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler  
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        simple_formatter = logging.Formatter('%(levelname)s: %(message)s')
        
        file_handler.setFormatter(detailed_formatter)
        console_handler.setFormatter(simple_formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Error context tracking
        self.error_context: Dict[str, Any] = {}
    
    def set_context(self, **kwargs) -> None:
        """Set context information for error reporting"""
        self.error_context.update(kwargs)
    
    def clear_context(self) -> None:
        """Clear error context"""
        self.error_context.clear()
    
    def log(self, message: str, level: str = "INFO", **kwargs) -> None:
        """Enhanced logging with context"""
        # Combine context with additional kwargs
        context = {**self.error_context, **kwargs}
        
        if context:
            context_str = " | ".join(f"{k}={v}" for k, v in context.items())
            message = f"{message} [{context_str}]"
        
        level_map = {
            "DEBUG": self.logger.debug,
            "INFO": self.logger.info,
            "WARNING": self.logger.warning,
            "ERROR": self.logger.error,
            "CRITICAL": self.logger.critical
        }
        
        log_func = level_map.get(level.upper(), self.logger.info)
        log_func(message)
    
    def log_exception(self, exc: Exception, message: str = "Exception occurred") -> None:
        """Log exception with full context and traceback"""
        self.logger.error(
            f"{message}: {exc}",
            exc_info=True,
            extra={"context": self.error_context}
        )
    
    def log_tool_error(self, tool_name: str, error: str, return_code: Optional[int] = None) -> None:
        """Log tool execution errors with structured information"""
        error_info = {
            "tool": tool_name,
            "error": error,
            "return_code": return_code,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.log(
            f"Tool execution failed: {tool_name}",
            "ERROR",
            **error_info
        )
    
    def export_error_summary(self) -> Dict[str, Any]:
        """Export error summary for reporting"""
        summary = {
            "total_errors": self._count_log_entries("ERROR"),
            "total_warnings": self._count_log_entries("WARNING"),
            "total_critical": self._count_log_entries("CRITICAL"),
            "log_file": str(self.log_file) if hasattr(self, 'log_file') else None,
            "generated_at": datetime.utcnow().isoformat()
        }
        return summary
    
    def _count_log_entries(self, level: str) -> int:
        """Count log entries of specific level"""
        if not hasattr(self, 'log_file') or not self.log_file.exists():
            return 0
        
        try:
            with open(self.log_file, 'r') as f:
                return sum(1 for line in f if f" - {level} - " in line)
        except Exception:
            return 0


class ErrorRecoveryManager:
    """Manages error recovery and retry strategies"""
    
    def __init__(self, logger: EnhancedLogger):
        self.logger = logger
        self.failure_counts = {}
        self.circuit_breakers = {}
    
    def retry_with_exponential_backoff(
        self,
        func: Callable,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        exceptions: tuple = (Exception,)
    ) -> Any:
        """Retry function with exponential backoff"""
        import time
        import random
        
        attempt = 0
        delay = base_delay
        
        while attempt < max_attempts:
            try:
                result = func()
                # Reset failure count on success
                func_name = getattr(func, '__name__', str(func))
                if func_name in self.failure_counts:
                    del self.failure_counts[func_name]
                return result
            except exceptions as e:
                attempt += 1
                func_name = getattr(func, '__name__', str(func))
                self.failure_counts[func_name] = self.failure_counts.get(func_name, 0) + 1
                
                if attempt < max_attempts:
                    # Add jitter to prevent thundering herd
                    jitter = random.uniform(0, 0.1) * delay
                    sleep_time = min(delay + jitter, max_delay)
                    
                    self.logger.log(
                        f"Retry attempt {attempt}/{max_attempts} for {func_name} after {sleep_time:.2f}s",
                        "WARNING",
                        error=str(e)
                    )
                    
                    time.sleep(sleep_time)
                    delay *= 2  # Exponential backoff
                else:
                    self.logger.log(
                        f"All retry attempts failed for {func_name}",
                        "ERROR",
                        attempts=max_attempts,
                        final_error=str(e)
                    )
                    raise
    
    def circuit_breaker(
        self,
        func: Callable,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0
    ) -> Any:
        """Implement circuit breaker pattern"""
        import time
        
        func_name = getattr(func, '__name__', str(func))
        current_time = time.time()
        
        # Check if circuit is open
        if func_name in self.circuit_breakers:
            breaker = self.circuit_breakers[func_name]
            if breaker['state'] == 'open':
                if current_time - breaker['last_failure'] < recovery_timeout:
                    self.logger.log(
                        f"Circuit breaker open for {func_name}",
                        "WARNING"
                    )
                    raise Exception(f"Circuit breaker open for {func_name}")
                else:
                    # Try to recover
                    breaker['state'] = 'half_open'
        
        try:
            result = func()
            # Reset circuit breaker on success
            if func_name in self.circuit_breakers:
                self.circuit_breakers[func_name]['failure_count'] = 0
                self.circuit_breakers[func_name]['state'] = 'closed'
            return result
        except Exception as e:
            # Increment failure count
            if func_name not in self.circuit_breakers:
                self.circuit_breakers[func_name] = {
                    'failure_count': 0,
                    'state': 'closed',
                    'last_failure': current_time
                }
            
            breaker = self.circuit_breakers[func_name]
            breaker['failure_count'] += 1
            breaker['last_failure'] = current_time
            
            if breaker['failure_count'] >= failure_threshold:
                breaker['state'] = 'open'
                self.logger.log(
                    f"Circuit breaker opened for {func_name}",
                    "ERROR",
                    failure_count=breaker['failure_count']
                )
            
            raise


class SafeExecutor:
    """Provides safe execution wrappers for various operations"""
    
    def __init__(self, logger: EnhancedLogger, recovery_manager: ErrorRecoveryManager):
        self.logger = logger
        self.recovery_manager = recovery_manager
    
    def safe_call(self, func: Callable, default_return=None, suppress_exceptions=True, *args, **kwargs):
        """Safely call a function with optional exception suppression"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.logger.log(f"Safe call to {func.__name__} failed: {e}", "ERROR")
            if suppress_exceptions:
                return default_return
            raise


# Global instances for easy access
enhanced_logger = EnhancedLogger()
recovery_manager = ErrorRecoveryManager(enhanced_logger)
safe_executor = SafeExecutor(enhanced_logger, recovery_manager)

# Convenience decorators
retry_on_failure = recovery_manager.retry_with_exponential_backoff
circuit_breaker = recovery_manager.circuit_breaker


# Global logger instance
logger = EnhancedLogger()


def safe_execute(
    default: Any = None,
    error_msg: str = "Operation failed",
    log_level: str = "ERROR",
    raise_on_error: bool = False
) -> Callable[[F], F]:
    """
    Decorator for safe function execution with enhanced error handling
    
    Args:
        default: Default value to return on error
        error_msg: Error message prefix
        log_level: Logging level for errors
        raise_on_error: Whether to raise exception after logging
    
    Returns:
        Decorated function with error handling
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except KeyboardInterrupt:
                logger.log("Operation interrupted by user", "INFO")
                raise
            except Exception as e:
                error_context = {
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()) if kwargs else []
                }
                
                logger.set_context(**error_context)
                logger.log_exception(e, f"{error_msg} in {func.__name__}")
                logger.clear_context()
                
                if raise_on_error:
                    raise
                    
                return default
                
        return wrapper
    return decorator


def validate_input(
    value: Any,
    validators: Dict[str, Any],
    field_name: str = "input"
) -> bool:
    """
    Enhanced input validation with multiple checks
    
    Args:
        value: Value to validate
        validators: Dictionary of validation rules
        field_name: Name of field being validated
    
    Returns:
        True if validation passes
        
    Raises:
        ValidationError: If validation fails
    """
    errors = []
    
    # Type validation
    if "type" in validators:
        expected_type = validators["type"]
        if not isinstance(value, expected_type):
            errors.append(f"{field_name} must be of type {expected_type.__name__}")
    
    # String-specific validations
    if isinstance(value, str):
        # Length validation
        if "max_length" in validators:
            max_len = validators["max_length"]
            if len(value) > max_len:
                errors.append(f"{field_name} exceeds maximum length of {max_len}")
        
        if "min_length" in validators:
            min_len = validators["min_length"]
            if len(value) < min_len:
                errors.append(f"{field_name} below minimum length of {min_len}")
        
        # Pattern validation
        if "pattern" in validators:
            pattern = validators["pattern"]
            if not pattern.match(value):
                errors.append(f"{field_name} does not match required pattern")
        
        # Forbidden content
        if "forbidden" in validators:
            forbidden = validators["forbidden"]
            for forbidden_item in forbidden:
                if forbidden_item.lower() in value.lower():
                    errors.append(f"{field_name} contains forbidden content: {forbidden_item}")
    
    # Numeric validations
    if isinstance(value, (int, float)):
        if "min_value" in validators:
            min_val = validators["min_value"]
            if value < min_val:
                errors.append(f"{field_name} below minimum value of {min_val}")
        
        if "max_value" in validators:
            max_val = validators["max_value"]
            if value > max_val:
                errors.append(f"{field_name} exceeds maximum value of {max_val}")
    
    # Empty value check
    if "allow_empty" in validators and not validators["allow_empty"]:
        if not value or (isinstance(value, str) and not value.strip()):
            errors.append(f"{field_name} cannot be empty")
    
    if errors:
        raise ValidationError(f"Validation failed for {field_name}: {'; '.join(errors)}")
    
    return True


@safe_execute(default=False, error_msg="File operation failed")
def safe_file_write(file_path: Path, content: str, encoding: str = "utf-8") -> bool:
    """
    Safely write content to file with error handling
    
    Args:
        file_path: Path to write to
        content: Content to write
        encoding: File encoding
        
    Returns:
        True if successful, False otherwise
    """
    # Input validation
    validate_input(str(file_path), {
        "type": str,
        "max_length": 1000,
        "forbidden": ["..", "/etc/", "/root/", "/bin/"]
    }, "file_path")
    
    validate_input(content, {
        "type": str,
        "max_length": 10 * 1024 * 1024  # 10MB limit
    }, "content")
    
    # Ensure parent directory exists
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Atomic write operation
    with open(file_path, 'w', encoding=encoding) as f:
        f.write(content)
    
    logger.log(f"Successfully wrote file: {file_path}", "DEBUG")
    return True


@safe_execute(default=None, error_msg="File read failed")
def safe_file_read(file_path: Path, encoding: str = "utf-8") -> Optional[str]:
    """
    Safely read file content with error handling
    
    Args:
        file_path: Path to read from
        encoding: File encoding
        
    Returns:
        File content or None on error
    """
    if not file_path.exists():
        logger.log(f"File not found: {file_path}", "WARNING")
        return None
    
    if not file_path.is_file():
        logger.log(f"Path is not a file: {file_path}", "WARNING") 
        return None
    
    # Check file size (limit to 50MB)
    if file_path.stat().st_size > 50 * 1024 * 1024:
        logger.log(f"File too large to read: {file_path}", "WARNING")
        return None
    
    with open(file_path, 'r', encoding=encoding) as f:
        content = f.read()
    
    logger.log(f"Successfully read file: {file_path}", "DEBUG")
    return content


def create_error_context(operation: str, **kwargs) -> Dict[str, Any]:
    """Create standardized error context for logging"""
    return {
        "operation": operation,
        "timestamp": datetime.utcnow().isoformat(),
        **kwargs
    }


class ErrorRecovery:
    """Error recovery and retry mechanisms"""
    
    @staticmethod
    def retry_operation(
        func: Callable,
        max_attempts: int = 3,
        delay_seconds: float = 1.0,
        backoff_factor: float = 2.0,
        exceptions: tuple = (Exception,)
    ) -> Any:
        """
        Retry operation with exponential backoff
        
        Args:
            func: Function to retry
            max_attempts: Maximum retry attempts
            delay_seconds: Initial delay between retries
            backoff_factor: Backoff multiplier
            exceptions: Exceptions to catch and retry on
            
        Returns:
            Function result
            
        Raises:
            Last exception if all retries fail
        """
        import time
        
        last_exception = None
        delay = delay_seconds
        
        for attempt in range(max_attempts):
            try:
                return func()
            except exceptions as e:
                last_exception = e
                
                if attempt < max_attempts - 1:
                    logger.log(
                        f"Retry attempt {attempt + 1}/{max_attempts} after {delay}s delay",
                        "WARNING",
                        error=str(e)
                    )
                    time.sleep(delay)
                    delay *= backoff_factor
                else:
                    logger.log(
                        f"All retry attempts failed for operation",
                        "ERROR",
                        attempts=max_attempts,
                        final_error=str(e)
                    )
        
        if last_exception:
            raise last_exception


# Additional utility functions for atomic operations
def atomic_write(file_path: Path, content: str, encoding: str = "utf-8") -> bool:
    """
    Perform atomic write operation using temporary file
    """
    import tempfile
    import shutil
    
    try:
        # Create temporary file in same directory to ensure same filesystem
        temp_dir = file_path.parent
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        with tempfile.NamedTemporaryFile(
            mode='w', 
            encoding=encoding, 
            dir=temp_dir, 
            delete=False,
            suffix='.tmp'
        ) as temp_file:
            temp_file.write(content)
            temp_name = temp_file.name
        
        # Atomic move
        shutil.move(temp_name, file_path)
        return True
        
    except Exception as e:
        logger.log(f"Atomic write failed: {e}", "ERROR")
        # Clean up temp file if it exists
        try:
            if 'temp_name' in locals():
                Path(temp_name).unlink(missing_ok=True)
        except:
            pass
        return False


def safe_json_load(file_path: Path, default: Any = None) -> Any:
    """Safely load JSON with error handling"""
    try:
        content = safe_file_read(file_path)
        if content is not None:
            return json.loads(content)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.log(f"JSON load failed for {file_path}: {e}", "WARNING")
    
    return default


def safe_json_save(file_path: Path, data: Any, indent: int = 2) -> bool:
    """Safely save JSON with error handling"""
    try:
        content = json.dumps(data, indent=indent, ensure_ascii=False)
        return atomic_write(file_path, content)
    except Exception as e:
        logger.log(f"JSON save failed for {file_path}: {e}", "ERROR")
        return False