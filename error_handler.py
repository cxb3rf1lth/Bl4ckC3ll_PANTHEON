#!/usr/bin/env python3
"""
Enhanced error handling and logging utilities for Bl4ckC3ll_PANTHEON
Provides structured error handling, logging, and recovery mechanisms
"""

import sys
import traceback
import functools
import logging
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
    """Configuration-related errors"""
    pass


class ToolExecutionError(SecurityTestingError):
    """External tool execution errors"""
    def __init__(self, tool_name: str, message: str, return_code: Optional[int] = None):
        self.tool_name = tool_name
        self.return_code = return_code
        super().__init__(f"{tool_name}: {message}")


class NetworkError(SecurityTestingError):
    """Network-related errors"""
    pass


class ValidationError(SecurityTestingError):
    """Input validation errors"""
    pass


class EnhancedLogger:
    """Enhanced logger with structured logging and error context"""
    
    def __init__(self, name: str = "Bl4ckC3ll_PANTHEON", log_dir: Optional[Path] = None):
        self.name = name
        self.log_dir = log_dir or Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup logging
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # File handler
        log_file = self.log_dir / f"{name}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
        
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
        log_file = self.log_dir / f"{self.name}.log"
        
        error_summary = {
            "timestamp": datetime.utcnow().isoformat(),
            "context": self.error_context,
            "log_file": str(log_file),
            "errors_count": self._count_log_entries("ERROR"),
            "warnings_count": self._count_log_entries("WARNING")
        }
        
        return error_summary
    
    def _count_log_entries(self, level: str) -> int:
        """Count log entries of specific level"""
        log_file = self.log_dir / f"{self.name}.log"
        
        if not log_file.exists():
            return 0
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                return sum(1 for line in f if f" - {level} - " in line)
        except Exception:
            return 0


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
                errors.append(f"{field_name} is below minimum length of {min_len}")
        
        # Pattern validation
        if "pattern" in validators:
            import re
            pattern = validators["pattern"]
            if not re.match(pattern, value):
                errors.append(f"{field_name} does not match required pattern")
        
        # Forbidden characters/strings
        if "forbidden" in validators:
            forbidden = validators["forbidden"]
            for forbidden_item in forbidden:
                if forbidden_item in value:
                    errors.append(f"{field_name} contains forbidden content: {forbidden_item}")
    
    # Numeric validations
    if isinstance(value, (int, float)):
        if "min_value" in validators:
            min_val = validators["min_value"]
            if value < min_val:
                errors.append(f"{field_name} is below minimum value of {min_val}")
        
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
    
    # Write with atomic operation
    temp_path = file_path.with_suffix(f"{file_path.suffix}.tmp")
    
    try:
        with open(temp_path, 'w', encoding=encoding) as f:
            f.write(content)
            f.flush()
        
        # Atomic move
        temp_path.replace(file_path)
        logger.log(f"Successfully wrote file: {file_path}", "DEBUG")
        return True
        
    except Exception as e:
        # Cleanup temp file on error
        if temp_path.exists():
            temp_path.unlink()
        raise


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