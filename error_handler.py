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
    
    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup main logger
        self.logger = logging.getLogger("pantheon_enhanced")
        self.logger.setLevel(logging.DEBUG)
        
        # Create handlers if they don't exist
        if not self.logger.handlers:
            # File handler for all logs
            file_handler = logging.FileHandler(
                self.log_dir / f"pantheon_{datetime.now().strftime('%Y%m%d')}.log"
            )
            file_handler.setLevel(logging.DEBUG)
            
            # Console handler for important messages
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            
            # Create formatters
            detailed_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            simple_formatter = logging.Formatter(
                '%(levelname)s: %(message)s'
            )
            
            file_handler.setFormatter(detailed_formatter)
            console_handler.setFormatter(simple_formatter)
            
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
    
    def log_with_context(self, level: str, message: str, context: Dict[str, Any] = None):
        """Log message with additional context information"""
        context = context or {}
        
        # Add timestamp and caller info to context
        context.update({
            'timestamp': datetime.now().isoformat(),
            'caller': traceback.extract_stack()[-2].name if traceback.extract_stack() else 'unknown'
        })
        
        log_entry = {
            'message': message,
            'context': context
        }
        
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(json.dumps(log_entry, indent=2) if context else message)
    
    def error(self, message: str, context: Dict[str, Any] = None, exc_info: bool = True):
        """Log error with full context and exception information"""
        if exc_info and sys.exc_info()[0]:
            context = context or {}
            context['exception'] = {
                'type': sys.exc_info()[0].__name__,
                'message': str(sys.exc_info()[1]),
                'traceback': traceback.format_exception(*sys.exc_info())
            }
        self.log_with_context('error', message, context)
    
    def warning(self, message: str, context: Dict[str, Any] = None):
        """Log warning with context"""
        self.log_with_context('warning', message, context)
    
    def info(self, message: str, context: Dict[str, Any] = None):
        """Log info with context"""
        self.log_with_context('info', message, context)
    
    def debug(self, message: str, context: Dict[str, Any] = None):
        """Log debug with context"""
        self.log_with_context('debug', message, context)


class ErrorRecoveryManager:
    """Manages error recovery and retry strategies"""
    
    def __init__(self, logger: EnhancedLogger):
        self.logger = logger
        self.failure_counts = {}
    
    def retry_with_exponential_backoff(
        self, 
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exceptions: tuple = (Exception,)
    ):
        """Decorator for retrying functions with exponential backoff"""
        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                last_exception = None
                
                for attempt in range(max_retries + 1):
                    try:
                        result = func(*args, **kwargs)
                        
                        # Reset failure count on success
                        func_name = f"{func.__module__}.{func.__name__}"
                        if func_name in self.failure_counts:
                            del self.failure_counts[func_name]
                        
                        return result
                        
                    except exceptions as e:
                        last_exception = e
                        func_name = f"{func.__module__}.{func.__name__}"
                        
                        # Track failure count
                        self.failure_counts[func_name] = self.failure_counts.get(func_name, 0) + 1
                        
                        if attempt < max_retries:
                            delay = min(base_delay * (2 ** attempt), max_delay)
                            self.logger.warning(
                                f"Function {func_name} failed (attempt {attempt + 1}/{max_retries + 1}), retrying in {delay:.1f}s",
                                {'function': func_name, 'attempt': attempt + 1, 'error': str(e), 'delay': delay}
                            )
                            import time
                            time.sleep(delay)
                        else:
                            self.logger.error(
                                f"Function {func_name} failed after {max_retries + 1} attempts",
                                {'function': func_name, 'total_attempts': max_retries + 1, 'final_error': str(e)}
                            )
                
                raise last_exception
            return wrapper
        return decorator
    
    def circuit_breaker(self, failure_threshold: int = 5, recovery_timeout: float = 300):
        """Circuit breaker pattern to prevent cascading failures"""
        def decorator(func: F) -> F:
            func_name = f"{func.__module__}.{func.__name__}"
            state = {'failures': 0, 'last_failure': 0, 'state': 'closed'}  # closed, open, half-open
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                import time
                now = time.time()
                
                # Check circuit state
                if state['state'] == 'open':
                    if now - state['last_failure'] > recovery_timeout:
                        state['state'] = 'half-open'
                        self.logger.info(f"Circuit breaker for {func_name} moving to half-open state")
                    else:
                        raise SecurityTestingError(f"Circuit breaker open for {func_name}")
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Success - reset or close circuit
                    if state['state'] in ['half-open', 'open']:
                        self.logger.info(f"Circuit breaker for {func_name} closing (success)")
                    state['failures'] = 0
                    state['state'] = 'closed'
                    
                    return result
                    
                except Exception as e:
                    state['failures'] += 1
                    state['last_failure'] = now
                    
                    if state['failures'] >= failure_threshold:
                        state['state'] = 'open'
                        self.logger.error(
                            f"Circuit breaker opened for {func_name} after {failure_threshold} failures",
                            {'function': func_name, 'failures': state['failures']}
                        )
                    
                    raise
            
            return wrapper
        return decorator


class SafeExecutor:
    """Safe execution context with enhanced error handling"""
    
    def __init__(self, logger: EnhancedLogger, recovery_manager: ErrorRecoveryManager):
        self.logger = logger
        self.recovery_manager = recovery_manager
    
    def execute_with_fallback(self, primary_func: Callable, fallback_funcs: list, *args, **kwargs):
        """Execute function with fallback options"""
        functions_to_try = [primary_func] + fallback_funcs
        
        for i, func in enumerate(functions_to_try):
            try:
                self.logger.debug(f"Attempting execution with {func.__name__}")
                result = func(*args, **kwargs)
                
                if i > 0:  # Used a fallback
                    self.logger.warning(f"Primary function failed, succeeded with fallback: {func.__name__}")
                
                return result
                
            except Exception as e:
                if i == len(functions_to_try) - 1:  # Last function failed
                    self.logger.error(f"All execution attempts failed, last error from {func.__name__}: {e}")
                    raise
                else:
                    self.logger.warning(f"Function {func.__name__} failed, trying fallback: {e}")
        
        raise SecurityTestingError("No valid execution path found")
    
    def safe_call(self, func: Callable, default_return=None, suppress_exceptions=True, *args, **kwargs):
        """Safely call a function with optional exception suppression"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.logger.error(f"Safe call to {func.__name__} failed: {e}")
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