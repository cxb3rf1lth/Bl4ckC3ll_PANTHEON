#!/usr/bin/env python3
"""
Test suite for security improvements and new modules
Tests configuration validation, error handling, and security utilities
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import our new modules
from config_validator import ConfigValidator, validate_configuration_file, create_secure_default_config
from error_handler import (
    EnhancedLogger,
    safe_execute,
    validate_input,
    ValidationError,
    safe_file_write,
    safe_file_read,
    ErrorRecovery,
)
from security_utils import InputSanitizer, NetworkValidator, SecureHeaders, RateLimiter, create_security_context


class TestConfigValidator:
    """Test configuration validation functionality"""

    def test_valid_config(self):
        """Test validation of valid configuration"""
        validator = ConfigValidator()
        config = create_secure_default_config()

        validated = validator.validate_config(config)
        assert validated is not None
        assert "repos" in validated
        assert "limits" in validated

    def test_invalid_repo_urls(self):
        """Test validation rejects invalid repository URLs"""
        validator = ConfigValidator()
        config = {
            "repos": {"BadRepo": "not-a-url", "LocalPath": "/local/path"},
            "limits": {"parallel_jobs": 10, "http_timeout": 15, "rps": 500, "max_concurrent_scans": 5},
        }

        with pytest.raises(ValueError):
            validator.validate_config(config)

    def test_invalid_limits(self):
        """Test validation rejects invalid limits"""
        validator = ConfigValidator()
        config = {
            "repos": {"Test": "https://github.com/test/repo.git"},
            "limits": {
                "parallel_jobs": -1,  # Invalid
                "http_timeout": 1000,  # Too high
                "rps": 0,  # Too low
                "max_concurrent_scans": 100,  # Too high
            },
        }

        with pytest.raises(ValueError):
            validator.validate_config(config)

    def test_security_validation(self):
        """Test security-focused validation"""
        validator = ConfigValidator()
        config = {
            "repos": {"Test": "https://github.com/test/repo.git"},
            "limits": {"parallel_jobs": 10, "http_timeout": 15, "rps": 500, "max_concurrent_scans": 5},
            "plugins": {"directory": "../../../etc/passwd"},  # Path traversal attempt
        }

        validated = validator.validate_config(config)
        assert len(validator.warnings) > 0  # Should generate warnings


class TestEnhancedLogger:
    """Test enhanced logging functionality"""

    def test_logger_creation(self):
        """Test logger can be created successfully"""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = EnhancedLogger("test", Path(temp_dir))
            assert logger.name == "test"
            assert logger.log_dir == Path(temp_dir)

    def test_context_management(self):
        """Test error context management"""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = EnhancedLogger("test", Path(temp_dir))

            logger.set_context(operation="test", target="example.com")
            assert "operation" in logger.error_context
            assert "target" in logger.error_context

            logger.clear_context()
            assert len(logger.error_context) == 0

    def test_logging_with_context(self):
        """Test logging with context information"""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = EnhancedLogger("test", Path(temp_dir))
            logger.set_context(test="value")

            # Should not raise exception
            logger.log("Test message", "INFO")
            logger.log("Error message", "ERROR")


class TestSafeExecuteDecorator:
    """Test safe execution decorator"""

    def test_successful_execution(self):
        """Test decorator with successful function execution"""

        @safe_execute(default="failed")
        def successful_function():
            return "success"

        result = successful_function()
        assert result == "success"

    def test_exception_handling(self):
        """Test decorator handles exceptions correctly"""

        @safe_execute(default="failed", raise_on_error=False)
        def failing_function():
            raise ValueError("Test error")

        result = failing_function()
        assert result == "failed"

    def test_keyboard_interrupt_passthrough(self):
        """Test decorator allows KeyboardInterrupt to pass through"""

        @safe_execute(default="failed")
        def interrupted_function():
            raise KeyboardInterrupt()

        with pytest.raises(KeyboardInterrupt):
            interrupted_function()


class TestInputValidation:
    """Test input validation functions"""

    def test_valid_input(self):
        """Test validation passes for valid input"""
        validators = {"type": str, "max_length": 10, "pattern": r"^[a-z]+$"}

        assert validate_input("test", validators, "test_field")

    def test_invalid_type(self):
        """Test validation fails for wrong type"""
        validators = {"type": str}

        with pytest.raises(ValidationError):
            validate_input(123, validators, "test_field")

    def test_length_validation(self):
        """Test string length validation"""
        validators = {"max_length": 5}

        with pytest.raises(ValidationError):
            validate_input("toolong", validators, "test_field")

    def test_pattern_validation(self):
        """Test pattern matching validation"""
        validators = {"pattern": r"^[a-z]+$"}

        with pytest.raises(ValidationError):
            validate_input("Test123", validators, "test_field")

    def test_forbidden_content(self):
        """Test forbidden content validation"""
        validators = {"forbidden": ["script", "eval"]}

        with pytest.raises(ValidationError):
            validate_input("some script tag", validators, "test_field")


class TestFileOperations:
    """Test safe file operation functions"""

    def test_safe_file_write_read(self):
        """Test safe file write and read operations"""
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "test.txt"
            content = "Test content"

            # Test write
            success = safe_file_write(file_path, content)
            assert success is True
            assert file_path.exists()

            # Test read
            read_content = safe_file_read(file_path)
            assert read_content == content

    def test_dangerous_path_rejection(self):
        """Test rejection of dangerous file paths"""
        dangerous_path = Path("/etc/passwd")

        # Should fail validation and return False
        success = safe_file_write(dangerous_path, "malicious content")
        assert success is False


class TestInputSanitizer:
    """Test input sanitization functionality"""

    def test_url_sanitization(self):
        """Test URL sanitization"""
        # Valid URL
        valid_url = "https://example.com/path"
        sanitized = InputSanitizer.sanitize_url(valid_url)
        assert sanitized is not None

        # Invalid URL with script
        malicious_url = "javascript:alert('xss')"
        sanitized = InputSanitizer.sanitize_url(malicious_url)
        assert sanitized is None

        # URL with path traversal
        traversal_url = "https://example.com/../../../etc/passwd"
        sanitized = InputSanitizer.sanitize_url(traversal_url)
        assert sanitized is None

    def test_domain_sanitization(self):
        """Test domain name sanitization"""
        # Valid domain
        valid_domain = "example.com"
        sanitized = InputSanitizer.sanitize_domain(valid_domain)
        assert sanitized == valid_domain

        # Invalid domain
        invalid_domain = "ex@mple.com"
        sanitized = InputSanitizer.sanitize_domain(invalid_domain)
        assert sanitized is None

        # Domain with path traversal
        malicious_domain = "example.com/../etc"
        sanitized = InputSanitizer.sanitize_domain(malicious_domain)
        assert sanitized is None

    def test_filename_sanitization(self):
        """Test filename sanitization"""
        # Valid filename
        valid_filename = "report.html"
        sanitized = InputSanitizer.sanitize_filename(valid_filename)
        assert sanitized == valid_filename

        # Filename with dangerous characters
        dangerous_filename = "report<script>.html"
        sanitized = InputSanitizer.sanitize_filename(dangerous_filename)
        assert sanitized == "reportscript.html"

        # Reserved Windows name
        reserved_filename = "CON.txt"
        sanitized = InputSanitizer.sanitize_filename(reserved_filename)
        assert sanitized is None

    def test_safe_path_validation(self):
        """Test safe path validation"""
        # Safe path
        safe_path = "/home/user/documents/report.txt"
        assert InputSanitizer.is_safe_path(safe_path) is True

        # Unsafe path with traversal
        unsafe_path = "/home/user/../../../etc/passwd"
        assert InputSanitizer.is_safe_path(unsafe_path) is False

        # System directory
        system_path = "/etc/passwd"
        assert InputSanitizer.is_safe_path(system_path) is False


class TestNetworkValidator:
    """Test network validation functionality"""

    def test_valid_domain_validation(self):
        """Test validation of valid domain names"""
        result = NetworkValidator.validate_target_host("example.com")
        assert result["valid"] is True
        assert result["type"] == "domain"
        assert result["domain"] == "example.com"

    def test_valid_ip_validation(self):
        """Test validation of valid IP addresses"""
        result = NetworkValidator.validate_target_host("8.8.8.8")
        assert result["valid"] is True
        assert result["type"] == "ip"
        assert result["ip_address"] == "8.8.8.8"

    def test_private_ip_warning(self):
        """Test private IP generates warning"""
        result = NetworkValidator.validate_target_host("192.168.1.1")
        assert result["valid"] is True
        assert len(result["warnings"]) > 0
        assert "private IP range" in result["warnings"][0]

    def test_reserved_ip_rejection(self):
        """Test reserved IP addresses are rejected"""
        result = NetworkValidator.validate_target_host("0.0.0.0")
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_invalid_host_rejection(self):
        """Test invalid hosts are rejected"""
        result = NetworkValidator.validate_target_host("invalid..domain")
        assert result["valid"] is False
        assert len(result["errors"]) > 0


class TestSecureHeaders:
    """Test security headers analysis"""

    def test_good_headers_analysis(self):
        """Test analysis of good security headers"""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
        }

        result = SecureHeaders.analyze_headers(headers)
        assert result["score"] > 0
        assert len(result["present_headers"]) == len(headers)

    def test_missing_headers_analysis(self):
        """Test analysis identifies missing security headers"""
        headers = {}  # No security headers

        result = SecureHeaders.analyze_headers(headers)
        assert result["score"] == 0
        assert len(result["missing_headers"]) > 0
        assert len(result["recommendations"]) > 0


class TestRateLimiter:
    """Test rate limiting functionality"""

    def test_rate_limiter_basic(self):
        """Test basic rate limiter functionality"""
        limiter = RateLimiter(requests_per_second=10.0, burst_limit=5)

        # Should be able to acquire tokens initially
        assert limiter.acquire(1) is True
        assert limiter.acquire(1) is True

    def test_rate_limiter_exhaustion(self):
        """Test rate limiter token exhaustion"""
        limiter = RateLimiter(requests_per_second=1.0, burst_limit=2)

        # Exhaust tokens
        assert limiter.acquire(1) is True
        assert limiter.acquire(1) is True
        assert limiter.acquire(1) is False  # Should be rate limited

    def test_rate_limiter_stats(self):
        """Test rate limiter statistics"""
        limiter = RateLimiter(requests_per_second=10.0, burst_limit=5)
        limiter.acquire(1)

        stats = limiter.get_stats()
        assert "current_tokens" in stats
        assert "requests_last_minute" in stats
        assert stats["requests_last_minute"] >= 1


class TestErrorRecovery:
    """Test error recovery mechanisms"""

    def test_successful_retry(self):
        """Test retry succeeds on second attempt"""
        attempt_count = 0

        def flaky_function():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 2:
                raise ValueError("Temporary failure")
            return "success"

        result = ErrorRecovery.retry_operation(flaky_function, max_attempts=3, delay_seconds=0.01)
        assert result == "success"
        assert attempt_count == 2

    def test_retry_exhaustion(self):
        """Test retry gives up after max attempts"""

        def always_failing_function():
            raise ValueError("Permanent failure")

        with pytest.raises(ValueError):
            ErrorRecovery.retry_operation(always_failing_function, max_attempts=2, delay_seconds=0.01)


class TestSecurityContext:
    """Test security context creation"""

    def test_security_context_creation(self):
        """Test security context is created properly"""
        context = create_security_context("subdomain_scan", "example.com")

        assert "timestamp" in context
        assert context["operation"] == "subdomain_scan"
        assert context["target"] == "example.com"
        assert "user" in context
        assert "hostname" in context
        assert context["authorized"] is False  # Default should be False


# Integration tests
class TestIntegration:
    """Integration tests for multiple components"""

    def test_config_validation_with_error_handling(self):
        """Test config validation with error handling integration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"

            # Create invalid config
            invalid_config = {"repos": {"BadRepo": "not-a-url"}, "limits": {"parallel_jobs": -1}}

            # Write config file
            with open(config_file, "w") as f:
                json.dump(invalid_config, f)

            # Should raise ValidationError
            with pytest.raises(ValueError):
                validate_configuration_file(config_file)

    def test_safe_operations_with_logging(self):
        """Test safe operations work with enhanced logging"""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = EnhancedLogger("integration_test", Path(temp_dir))

            @safe_execute(default=None, error_msg="Test operation failed")
            def test_operation():
                return "success"

            result = test_operation()
            assert result == "success"


if __name__ == "__main__":
    # Run tests if script is executed directly
    pytest.main([__file__, "-v"])
