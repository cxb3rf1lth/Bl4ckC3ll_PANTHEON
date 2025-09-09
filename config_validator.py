#!/usr/bin/env python3
"""
Configuration validation utilities for Bl4ckC3ll_PANTHEON
Provides enhanced validation, sanitization, and configuration management
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from urllib.parse import urlparse


class ConfigValidator:
    """Enhanced configuration validator with security checks"""
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and sanitize configuration with comprehensive checks
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            Validated and sanitized configuration
            
        Raises:
            ValueError: If critical validation errors are found
        """
        self.errors.clear()
        self.warnings.clear()
        
        validated_config = self._deep_copy_config(config)
        
        # Core validation checks
        self._validate_repos(validated_config.get("repos", {}))
        self._validate_limits(validated_config.get("limits", {}))
        self._validate_nuclei_config(validated_config.get("nuclei", {}))
        self._validate_report_config(validated_config.get("report", {}))
        self._validate_paths(validated_config)
        
        # Security checks
        self._security_validation(validated_config)
        
        if self.errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(self.errors)}")
            
        if self.warnings:
            print(f"Configuration warnings: {'; '.join(self.warnings)}")
            
        return validated_config
    
    def _deep_copy_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a deep copy of configuration for safe modification"""
        return json.loads(json.dumps(config))
    
    def _validate_repos(self, repos: Dict[str, str]) -> None:
        """Validate repository URLs"""
        if not repos:
            self.warnings.append("No repositories configured")
            return
            
        for name, url in repos.items():
            if not self._is_valid_url(url):
                self.errors.append(f"Invalid repository URL for {name}: {url}")
            elif not self._is_safe_git_url(url):
                self.warnings.append(f"Repository URL may not be secure: {name}")
    
    def _validate_limits(self, limits: Dict[str, Any]) -> None:
        """Validate resource limits"""
        required_limits = {
            "parallel_jobs": (1, 100),
            "http_timeout": (5, 300),
            "rps": (1, 10000),
            "max_concurrent_scans": (1, 50)
        }
        
        for limit_name, (min_val, max_val) in required_limits.items():
            if limit_name not in limits:
                self.warnings.append(f"Missing limit configuration: {limit_name}")
                continue
                
            value = limits[limit_name]
            if not isinstance(value, int) or value < min_val or value > max_val:
                self.errors.append(
                    f"Invalid {limit_name}: {value} (must be between {min_val} and {max_val})"
                )
    
    def _validate_nuclei_config(self, nuclei: Dict[str, Any]) -> None:
        """Validate Nuclei scanner configuration"""
        if not nuclei.get("enabled", True):
            return
            
        # Validate severity levels
        if "severity" in nuclei:
            valid_severities = {"info", "low", "medium", "high", "critical"}
            severities = set(nuclei["severity"].split(","))
            invalid = severities - valid_severities
            if invalid:
                self.errors.append(f"Invalid Nuclei severities: {invalid}")
        
        # Validate rate limiting
        for rate_param in ["rps", "conc"]:
            if rate_param in nuclei:
                value = nuclei[rate_param]
                if not isinstance(value, int) or value < 1 or value > 2000:
                    self.errors.append(f"Invalid Nuclei {rate_param}: {value}")
    
    def _validate_report_config(self, report: Dict[str, Any]) -> None:
        """Validate report generation configuration"""
        valid_formats = {"html", "json", "csv", "xml", "sarif", "junit"}
        
        if "formats" in report:
            formats = set(report["formats"])
            invalid = formats - valid_formats
            if invalid:
                self.errors.append(f"Invalid report formats: {invalid}")
    
    def _validate_paths(self, config: Dict[str, Any]) -> None:
        """Validate file paths in configuration"""
        # Check plugins directory if specified
        plugins_config = config.get("plugins", {})
        if "directory" in plugins_config:
            plugin_dir = Path(plugins_config["directory"])
            if not plugin_dir.exists():
                self.warnings.append(f"Plugin directory does not exist: {plugin_dir}")
    
    def _security_validation(self, config: Dict[str, Any]) -> None:
        """Perform security-focused validation checks"""
        # Check for potentially dangerous configurations
        self._check_dangerous_paths(config)
        self._check_resource_limits(config)
        self._validate_input_sanitization(config)
    
    def _check_dangerous_paths(self, config: Dict[str, Any]) -> None:
        """Check for potentially dangerous file paths"""
        dangerous_patterns = [
            r"\.\.\/",  # Path traversal
            r"\/etc\/",  # System directories
            r"\/root\/",  # Root directory
            r"\/bin\/",  # Binary directories
        ]
        
        config_str = json.dumps(config)
        for pattern in dangerous_patterns:
            if re.search(pattern, config_str):
                self.warnings.append(f"Potentially dangerous path pattern found: {pattern}")
    
    def _check_resource_limits(self, config: Dict[str, Any]) -> None:
        """Validate resource limits for security"""
        limits = config.get("limits", {})
        
        # Check for resource exhaustion risks
        if limits.get("parallel_jobs", 0) > 50:
            self.warnings.append("High parallel job count may cause resource exhaustion")
            
        if limits.get("rps", 0) > 5000:
            self.warnings.append("High RPS may trigger rate limiting or DoS protection")
    
    def _validate_input_sanitization(self, config: Dict[str, Any]) -> None:
        """Check for proper input sanitization settings"""
        # Ensure input validation is properly configured
        if not config.get("input_validation", {}).get("enabled", True):
            self.warnings.append("Input validation is disabled - security risk")
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid"""
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc and parsed.scheme in ["http", "https", "git"])
        except Exception:
            return False
    
    def _is_safe_git_url(self, url: str) -> bool:
        """Check if Git URL is from a trusted source"""
        trusted_domains = {
            "github.com",
            "gitlab.com", 
            "bitbucket.org"
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            return any(trusted in domain for trusted in trusted_domains)
        except Exception:
            return False


def validate_configuration_file(config_path: Path) -> Dict[str, Any]:
    """
    Load and validate configuration from file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Validated configuration dictionary
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON
        ValueError: If configuration validation fails
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in config file: {e}")
    
    validator = ConfigValidator()
    return validator.validate_config(config)


def create_secure_default_config() -> Dict[str, Any]:
    """Create a secure default configuration with proper validation"""
    return {
        "repos": {
            "SecLists": "https://github.com/danielmiessler/SecLists.git",
            "NucleiTemplates": "https://github.com/projectdiscovery/nuclei-templates.git"
        },
        "limits": {
            "parallel_jobs": 10,
            "http_timeout": 15,
            "rps": 500,
            "max_concurrent_scans": 5,
            "max_subdomain_depth": 2,
            "max_crawl_time": 300
        },
        "nuclei": {
            "enabled": True,
            "severity": "medium,high,critical",
            "rps": 500,
            "conc": 50,
            "timeout": 30
        },
        "report": {
            "formats": ["html", "json"],
            "auto_open_html": False,
            "include_viz": True
        },
        "input_validation": {
            "enabled": True,
            "max_url_length": 2048,
            "allowed_schemes": ["http", "https"],
            "sanitize_inputs": True
        }
    }