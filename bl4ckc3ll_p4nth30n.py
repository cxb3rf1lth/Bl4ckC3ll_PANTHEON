#!/usr/bin/env python3
# Bl4CkC3ll_P4NTH30N — Cleaned Orchestrator (Recon + Vuln scan + Report + Plugins)
# Author: @cxb3rf1lth
# Notes:
# - This is a deduplicated, hardened, and runnable version focused on reliability.
# - Exploitation stage is intentionally a no-op placeholder. Only scan/report is implemented.
# - External tools (subfinder, amass, naabu, httpx, nuclei) are optional; the code skips gracefully when missing.

import os
import sys
import shlex
import json
import time
import subprocess
import platform
import tempfile
import shutil
import uuid
import threading
import webbrowser
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util

# ---------- App meta ----------
APP = "Bl4CkC3ll_P4NTH30N"
AUTHOR = "@cxb3rf1lth"
VERSION = "9.0.0-clean"
HERE = Path(__file__).resolve().parent
TARGETS = HERE / "targets.txt"
RUNS_DIR = HERE / "runs"
LOG_DIR = HERE / "logs"
EXT_DIR = HERE / "external_lists"
EXTRA_DIR = HERE / "wordlists_extra"
MERGED_DIR = HERE / "lists_merged"
CFG_FILE = HERE / "p4nth30n.cfg.json"
PAYLOADS_DIR = HERE / "payloads"
EXPLOITS_DIR = HERE / "exploits"
PLUGINS_DIR = HERE / "plugins"
BACKUP_DIR = HERE / "backups"

# ---------- Configuration ----------
DEFAULT_CFG: Dict[str, Any] = {
    "repos": {
        "SecLists": "https://github.com/danielmiessler/SecLists.git",
        "PayloadsAllTheThings": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "Exploits": "https://github.com/offensive-security/exploitdb.git",
        "NucleiTemplates": "https://github.com/projectdiscovery/nuclei-templates.git",
        "Wordlists": "https://github.com/berzerk0/Probable-Wordlists.git",
        "FuzzDB": "https://github.com/fuzzdb-project/fuzzdb.git",
        "WebShells": "https://github.com/tennc/webshell.git",
        # Enhanced Community Nuclei Templates
        "NucleiCommunity": "https://github.com/geeknik/the-nuclei-templates.git",
        "NucleiFuzzing": "https://github.com/projectdiscovery/fuzzing-templates.git",
        "CustomNuclei": "https://github.com/panch0r3d/nuclei-templates.git",
        "KnightSec": "https://github.com/knightsec/nuclei-templates-ksec.git",
        "AdditionalWordlists": "https://github.com/assetnote/commonspeak2-wordlists.git",
        "OneListForAll": "https://github.com/six2dez/OneListForAll.git",
        "WebDiscoveryWordlists": "https://github.com/Bo0oM/fuzz.txt.git",
        "XSSPayloads": "https://github.com/payloadbox/xss-payload-list.git",
        "SQLIPayloads": "https://github.com/payloadbox/sql-injection-payload-list.git"
    },
    "limits": {
        "parallel_jobs": 20,
        "http_timeout": 15,
        "rps": 500,
        "max_concurrent_scans": 8,
        "http_revalidation_timeout": 8,
        "max_subdomain_depth": 3,
        "max_crawl_time": 600
    },
    "nuclei": {
        "enabled": True,
        "severity": "low,medium,high,critical",
        "rps": 800,
        "conc": 150,
        "all_templates": True,
        "keep_info_severity": False,
        "custom_templates": True,
        "disable_cluster_bomb": False,
        "community_templates": True,
        "template_sources": [
            "~/nuclei-templates",
            "~/nuclei-community",
            "~/nuclei-fuzzing",
            "~/custom-nuclei",
            "~/nuclei-ksec"
        ],
        "update_templates": True,
        "template_categories": "all",
        "exclude_templates": [],
        "custom_payloads": True
    },
    "endpoints": {
        "use_gau": True,
        "use_katana": True,
        "use_waybackurls": True,
        "use_gospider": True,
        "max_urls_per_target": 5000,
        "katana_depth": 2,
        "gospider_depth": 3
    },
    "advanced_scanning": {
        "ssl_analysis": True,
        "dns_enumeration": True,
        "technology_detection": True,
        "certificate_transparency": True,
        "subdomain_takeover": True,
        "cors_analysis": True,
        "security_headers": True,
        "api_discovery": True,
        "graphql_testing": True,
        "jwt_analysis": True,
        "cloud_storage_buckets": True,
        "container_scanning": True,
        "shodan_integration": True,
        "threat_intelligence": True,
        "compliance_checks": True
    },
    "fuzzing": {
        "enable_dirb": True,
        "enable_gobuster": True,
        "enable_ffuf": True,
        "enable_feroxbuster": True,
        "wordlist_size": "medium",
        "extensions": "php,asp,aspx,jsp,html,htm,txt,bak,old,conf,json,xml,yaml,yml,config",
        "advanced_fuzzing": True,
        "recursive_fuzzing": True,
        "status_codes": "200,201,202,204,301,302,303,307,308,401,403,405,500",
        "threads": 50,
        "wordlist_sources": ["seclists", "common", "big", "directory-list", "custom"],
        "parameter_fuzzing": True,
        "subdomain_fuzzing": True
    },
    "xss_testing": {
        "enabled": True,
        "xss_strike": True,
        "custom_payloads": True,
        "reflected_xss": True,
        "stored_xss": True,
        "dom_xss": True,
        "blind_xss": True,
        "payload_encoding": True,
        "bypass_filters": True
    },
    "subdomain_takeover": {
        "enabled": True,
        "subjack": True,
        "subzy": True,
        "nuclei_takeover": True,
        "custom_signatures": True,
        "timeout": 30,
        "threads": 10
    },
    "nmap_scanning": {
        "enabled": True,
        "quick_scan": True,
        "full_scan": False,
        "stealth_scan": True,
        "service_detection": True,
        "os_detection": True,
        "script_scanning": True,
        "vulnerability_scripts": True,
        "top_ports": 1000,
        "timing": 4,
        "custom_scripts": []
    },
    "sqlmap_testing": {
        "enabled": True,
        "crawl_depth": 1,                 # Reduced from 2
        "level": 2,                       # Reduced from 3
        "risk": 2,
        "techniques": "BEUST",
        "threads": 2,                     # Reduced from 5
        "batch_mode": True,
        "tamper_scripts": [],
        "custom_payloads": True,
        "time_based": True,
        "error_based": True,
        "union_based": True,
        "timeout": 600,                   # Add timeout setting
        "max_retries": 1                  # Add retry limit
    },
    "report": {
        "formats": ["html", "json", "csv", "sarif"],
        "auto_open_html": True,
        "include_viz": True,
        "risk_scoring": True,
        "vulnerability_correlation": True,
        "executive_summary": True
    },
    "plugins": {
        "enabled": True,
        "directory": str(PLUGINS_DIR),
        "auto_execute": False
    },
    "fallback": {
        "enabled": True,
        "direct_downloads": True,
        "mirror_sites": True
    },
    "resource_management": {
        "cpu_threshold": 75,              # Reduced from 85
        "memory_threshold": 80,           # Reduced from 90
        "disk_threshold": 90,             # Reduced from 95
        "monitor_interval": 3,            # Reduced for more frequent monitoring
        "auto_cleanup": True,
        "cache_enabled": True,
        "max_cache_size_mb": 1024
    },
    "error_handling": {
        "max_retries": 3,
        "retry_delay": 2,
        "continue_on_error": True,
        "log_level": "INFO",
        "graceful_degradation": True,
        "failover_tools": True
    },
    "validation": {
        "validate_tools_on_startup": True,
        "check_dependencies": True,
        "warn_on_missing_tools": True,
        "verify_target_reachability": True,
        "pre_scan_validation": True
    },
    "authentication": {
        "enabled": False,
        "cookies_file": "",
        "headers_file": "",
        "basic_auth": "",
        "bearer_token": ""
    },
    "network_analysis": {
        "traceroute": True,
        "whois_lookup": True,
        "reverse_dns": True,
        "asn_lookup": True,
        "geolocation": True
    },
    "api_security": {
        "enabled": True,
        "swagger_discovery": True,
        "openapi_analysis": True,
        "rest_api_fuzzing": True,
        "graphql_introspection": True,
        "soap_testing": True,
        "rate_limit_testing": True,
        "authentication_bypass": True
    },
    "cloud_security": {
        "enabled": True,
        "aws_s3_buckets": True,
        "azure_storage": True,
        "gcp_buckets": True,
        "cloud_metadata": True,
        "container_registries": True,
        "kubernetes_discovery": True
    },
    "threat_intelligence": {
        "enabled": True,
        "virustotal_api": "",
        "shodan_api": "",
        "censys_api": "",
        "passive_total_api": "",
        "malware_detection": True,
        "reputation_checks": True,
        "ioc_correlation": True
    },
    "ml_analysis": {
        "enabled": True,
        "false_positive_reduction": True,
        "vulnerability_prioritization": True,
        "anomaly_detection": True,
        "pattern_recognition": True,
        "risk_scoring_ml": True
    },
    "compliance": {
        "enabled": True,
        "owasp_top10": True,
        "nist_framework": True,
        "pci_dss": True,
        "gdpr_checks": True,
        "hipaa_checks": True,
        "iso27001": True
    },
    "cicd_integration": {
        "enabled": False,
        "github_actions": True,
        "gitlab_ci": True,
        "jenkins": True,
        "webhook_notifications": True,
        "api_endpoints": True,
        "scheduled_scans": True
    }
}

# ---------- Logging ----------
class Logger:
    def __init__(self):
        self.log_file = LOG_DIR / "bl4ckc3ll_p4nth30n.log"
        self.console_lock = threading.Lock()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - {level} - {message}"
        with self.console_lock:
            if level == "INFO":
                print(f"\033[94m{log_message}\033[0m")
            elif level == "WARNING":
                print(f"\033[93m{log_message}\033[0m")
            elif level == "ERROR":
                print(f"\033[91m{log_message}\033[0m")
            elif level == "SUCCESS":
                print(f"\033[92m{log_message}\033[0m")
            elif level == "DEBUG":
                print(f"\033[90m{log_message}\033[0m")
            else:
                print(log_message)
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_message + "\n")
        except Exception:
            pass

logger = Logger()

# ---------- Error Handling Helpers ----------
def safe_execute(func, *args, default=None, error_msg="Operation failed", log_level="ERROR", **kwargs):
    """Safely execute a function with standardized error handling"""
    try:
        return func(*args, **kwargs)
    except FileNotFoundError as e:
        logger.log(f"{error_msg} - File not found: {e}", log_level)
        return default
    except PermissionError as e:
        logger.log(f"{error_msg} - Permission denied: {e}", log_level)
        return default
    except subprocess.TimeoutExpired as e:
        logger.log(f"{error_msg} - Timeout: {e}", log_level)
        return default
    except Exception as e:
        logger.log(f"{error_msg}: {e}", log_level)
        return default

def safe_file_operation(operation, path, *args, **kwargs):
    """Safely perform file operations with proper error handling"""
    try:
        return operation(path, *args, **kwargs)
    except FileNotFoundError:
        logger.log(f"File not found: {path}", "ERROR")
        return None
    except PermissionError:
        logger.log(f"Permission denied accessing: {path}", "ERROR")
        return None
    except IsADirectoryError:
        logger.log(f"Expected file but found directory: {path}", "ERROR")
        return None
    except OSError as e:
        logger.log(f"OS error accessing {path}: {e}", "ERROR")
        return None
    except Exception as e:
        logger.log(f"Unexpected error with {path}: {e}", "ERROR")
        return None

def validate_input(value: str, pattern: str = None, max_length: int = 1000, allow_empty: bool = False) -> bool:
    """Validate user input with security considerations"""
    if not value and not allow_empty:
        return False
    
    if len(value) > max_length:
        logger.log(f"Input too long: {len(value)} > {max_length}", "WARNING")
        return False
    
    # Basic security checks
    dangerous_patterns = [
        r'[;&|`$(){}[\]\\]',  # Command injection patterns
        r'\.\./',             # Path traversal
        r'<script',           # XSS patterns
        r'javascript:',       # JavaScript injection
    ]
    
    import re
    for dangerous in dangerous_patterns:
        if re.search(dangerous, value, re.IGNORECASE):
            logger.log(f"Potentially dangerous input detected: {value[:50]}", "WARNING")
            return False
    
    # Optional pattern validation
    if pattern and not re.match(pattern, value):
        return False
    
    return True

# ---------- Utility Functions ----------
def create_resource_monitor_thread(cfg: Dict[str, Any]) -> Tuple[threading.Event, threading.Thread]:
    """Create and start a resource monitoring thread"""
    stop_event = threading.Event()
    monitor_thread = threading.Thread(
        target=resource_monitor, 
        args=(cfg, stop_event), 
        daemon=True
    )
    monitor_thread.start()
    return stop_event, monitor_thread

def cleanup_resource_monitor(stop_event: threading.Event, monitor_thread: threading.Thread):
    """Safely cleanup resource monitoring thread"""
    try:
        stop_event.set()
        monitor_thread.join(timeout=5)  # Don't wait forever
    except Exception as e:
        logger.log(f"Error cleaning up resource monitor: {e}", "WARNING")

def safe_http_request(url: str, timeout: int = 10, headers: Dict[str, str] = None) -> Optional[str]:
    """Safely make HTTP requests with proper error handling and validation"""
    if not validate_input(url, max_length=2000):
        logger.log(f"Invalid URL for HTTP request: {url[:100]}", "WARNING") 
        return None
    
    # Rate limiting to be respectful
    import time
    time.sleep(0.1)  # 100ms delay between requests
    
    # Use curl for consistent behavior with optimized settings
    cmd = ["curl", "-s", "-k", "-L", "-m", str(timeout), "--max-redirs", "3"]
    
    # Add User-Agent to be more respectful
    cmd.extend(["-H", "User-Agent: Bl4ckC3ll_PANTHEON/9.0.0 Security Scanner"])
    
    if headers:
        for key, value in headers.items():
            if validate_input(key) and validate_input(value):
                cmd.extend(["-H", f"{key}: {value}"])
    
    cmd.append(url)
    
    result = safe_execute(
        run_cmd,
        cmd,
        capture=True, 
        timeout=timeout + 5,
        check_return=False,
        default=None,
        error_msg=f"HTTP request failed for {url}",
        log_level="DEBUG"
    )
    
    return result.stdout if result else None

def execute_tool_safely(tool_name: str, args: List[str], timeout: int = 300, 
                       output_file: Optional[Path] = None) -> bool:
    """Safely execute security tools with standardized error handling"""
    if not which(tool_name):
        logger.log(f"Tool not available: {tool_name}", "WARNING")
        return False
    
    # Validate arguments
    for arg in args:
        if isinstance(arg, str) and not validate_input(arg, max_length=500):
            logger.log(f"Invalid argument for {tool_name}: {arg[:50]}", "WARNING")
            return False
    
    cmd = [tool_name] + args
    result = safe_execute(
        run_cmd,
        cmd,
        capture=bool(output_file),
        timeout=timeout,
        default=None,
        error_msg=f"Tool execution failed: {tool_name}"
    )
    
    if result and output_file and hasattr(result, 'stdout'):
        return atomic_write(output_file, result.stdout)
    
    return result is not None

# ---------- Utils ----------
def _bump_path() -> None:
    """Update PATH environment variable to include common binary locations"""
    envpath = os.environ.get("PATH", "")
    home = Path.home()
    add = [
        home / ".local/bin",
        home / "go/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/opt/metasploit-framework/bin",
    ]
    for p in add:
        s = str(p)
        if s not in envpath:
            envpath = s + os.pathsep + envpath
    os.environ["PATH"] = envpath
    logger.log(f"PATH updated", "DEBUG")

_bump_path()

def ts() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def atomic_write(path: Path, data: str) -> bool:
    """Atomically write data to a file with proper error handling"""
    def _write_operation():
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", delete=False, dir=path.parent, encoding="utf-8") as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, path)
        return True
    
    return safe_execute(
        _write_operation,
        default=False,
        error_msg=f"Failed to write file {path}"
    )

def read_lines(path: Path) -> List[str]:
    """Read lines from a file, ignoring comments and empty lines"""
    if not path.exists():
        return []
    
    def _read_operation():
        out: List[str] = []
        for l in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = l.strip()
            if s and not s.startswith("#"):
                out.append(s)
        return out
    
    return safe_execute(
        _read_operation,
        default=[],
        error_msg=f"Failed to read file {path}",
        log_level="WARNING"
    )

def write_uniq(path: Path, items: List[str]) -> bool:
    """Write unique items to file, removing duplicates"""
    seen = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return atomic_write(path, "\n".join(out) + ("\n" if out else ""))

def os_kind() -> str:
    s = platform.system().lower()
    if s == "darwin":
        return "mac"
    if s == "linux":
        try:
            import distro  # type: ignore
            d = distro.id().lower()
            if d in {"arch", "manjaro", "endeavouros"}:
                return "arch"
            return "debian"
        except Exception:
            return "debian"
    return "debian"

def run_cmd(cmd,
            cwd: Optional[Path] = None,
            env: Optional[Dict[str, str]] = None,
            timeout: int = 0,
            retries: int = 0,
            backoff: float = 1.6,
            capture: bool = True,
            check_return: bool = True,
            use_shell: bool = False) -> subprocess.CompletedProcess:
    if isinstance(cmd, str):
        args = cmd if use_shell else shlex.split(cmd)
    else:
        args = cmd
    attempt = 0
    last_exc: Optional[Exception] = None
    while True:
        t0 = time.time()
        try:
            p = subprocess.run(
                args,
                cwd=str(cwd) if cwd else None,
                env=env,
                text=True,
                capture_output=capture,
                timeout=timeout if timeout and timeout > 0 else None,
                shell=use_shell
            )
            dt = round(time.time() - t0, 3)
            if p.stdout:
                logger.log(f"STDOUT [{getattr(args,'__class__',type(args)).__name__}]: {p.stdout[:2000]}", "DEBUG")
            if p.stderr:
                logger.log(f"STDERR: {p.stderr[:2000]}", "DEBUG")
            if check_return and p.returncode != 0:
                raise RuntimeError(f"Command failed rc={p.returncode}")
            return p
        except subprocess.TimeoutExpired:
            last_exc = RuntimeError("timeout")
            logger.log(f"Timeout: {args if isinstance(args, list) else cmd}", "ERROR")
        except Exception as e:
            last_exc = e
            logger.log(f"Command error: {args if isinstance(args, list) else cmd} -> {e}", "ERROR")
        attempt += 1
        if attempt > retries:
            raise last_exc  # type: ignore
        sleep_for = backoff ** attempt
        logger.log(f"Retrying in {sleep_for:.1f}s (attempt {attempt}/{retries})", "WARNING")
        time.sleep(sleep_for)

def ensure_layout():
    for d in [RUNS_DIR, LOG_DIR, EXT_DIR, EXTRA_DIR, MERGED_DIR, PAYLOADS_DIR, EXPLOITS_DIR, PLUGINS_DIR, BACKUP_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    for f in ["paths_extra.txt", "vhosts_extra.txt", "params_extra.txt", "exploit_payloads.txt"]:
        (EXTRA_DIR / f).touch(exist_ok=True)
    if not TARGETS.exists():
        atomic_write(TARGETS, "example.com\n")
    if not CFG_FILE.exists():
        atomic_write(CFG_FILE, json.dumps(DEFAULT_CFG, indent=2))

def load_cfg() -> Dict[str, Any]:
    """Load and validate configuration"""
    ensure_layout()
    try:
        cfg_data = json.loads(CFG_FILE.read_text(encoding="utf-8"))
        # Validate critical configuration sections
        return _validate_configuration(cfg_data)
    except Exception as e:
        logger.log(f"Configuration load error: {e}, using defaults", "WARNING")
        return DEFAULT_CFG.copy()

def _validate_configuration(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Validate configuration values and apply safe defaults"""
    # Create a copy to avoid modifying the original
    validated_cfg = cfg.copy()
    
    # Validate limits section
    limits = validated_cfg.get("limits", {})
    limits["max_concurrent_scans"] = max(1, min(limits.get("max_concurrent_scans", 8), 20))
    limits["http_timeout"] = max(5, min(limits.get("http_timeout", 15), 300))
    limits["rps"] = max(1, min(limits.get("rps", 500), 2000))
    validated_cfg["limits"] = limits
    
    # Validate nuclei section
    nuclei = validated_cfg.get("nuclei", {})
    nuclei["rps"] = max(1, min(nuclei.get("rps", 800), 2000))
    nuclei["conc"] = max(1, min(nuclei.get("conc", 150), 500))
    validated_cfg["nuclei"] = nuclei
    
    # Ensure resource management section exists
    if "resource_management" not in validated_cfg:
        validated_cfg["resource_management"] = {
            "monitor_interval": 5,
            "cpu_threshold": 80,
            "memory_threshold": 80,
            "disk_threshold": 90
        }
    
    return validated_cfg

def save_cfg(cfg: Dict[str, Any]):
    atomic_write(CFG_FILE, json.dumps(cfg, indent=2))

def which(tool: str) -> bool:
    return shutil.which(tool) is not None

# ---------- Dependency validation ----------
def _check_python_version() -> bool:
    """Check if Python version meets requirements"""
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 9):
        logger.log(f"Python 3.9+ required, found {python_version.major}.{python_version.minor}", "ERROR")
        return False
    return True

def _check_python_packages() -> List[str]:
    """Check optional Python packages and return missing ones"""
    missing_packages = []
    
    packages_to_check = {
        "psutil": "System monitoring",
        "distro": "OS detection", 
        "requests": "HTTP operations"
    }
    
    for package, description in packages_to_check.items():
        try:
            __import__(package)
            logger.log(f"{package} available for {description.lower()}", "DEBUG")
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logger.log(f"Optional packages missing: {', '.join(missing_packages)}", "WARNING")
        logger.log("Install with: pip3 install " + " ".join(missing_packages), "INFO")
        logger.log("Or run: pip3 install -r requirements.txt", "INFO")
    
    return missing_packages

def _get_security_tools_config() -> Dict[str, str]:
    """Get configuration for security tools and their install commands"""
    return {
        # Core recon tools
        "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest", 
        "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "gau": "github.com/lc/gau/v2/cmd/gau@latest",
        # Enhanced tools
        "amass": "github.com/owasp-amass/amass/v4/cmd/amass@master",
        "masscan": "apt install masscan",
        "gobuster": "go install github.com/OJ/gobuster/v3@latest",
        "dirb": "apt install dirb", 
        "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
        "feroxbuster": "go install github.com/epi052/feroxbuster@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "gospider": "go install github.com/jaeles-project/gospider@latest",
        "subjack": "go install github.com/haccer/subjack@latest",
        "subzy": "go install github.com/LukaSikic/subzy@latest",
        "whatweb": "apt install whatweb",
        "wappalyzer": "npm install -g wappalyzer",
        "nikto": "apt install nikto",
        "sqlmap": "apt install sqlmap",
        "commix": "apt install commix",
        "xssstrike": "pip3 install xssstrike",
        "nmap": "apt install nmap",
        "dirsearch": "pip3 install dirsearch",
        "paramspider": "go install github.com/devanshbatham/paramspider@latest",
        "arjun": "pip3 install arjun",
        "dalfox": "go install github.com/hahwul/dalfox/v2@latest"
    }

def _check_security_tools() -> Tuple[List[str], List[Tuple[str, str]], int]:
    """Check security tools availability"""
    tools = _get_security_tools_config()
    core_tools = ["subfinder", "httpx", "naabu", "nuclei", "katana", "gau", "ffuf", "nmap", "sqlmap"]
    
    available_tools = []
    missing_tools = []
    
    for tool, install_cmd in tools.items():
        if which(tool):
            available_tools.append(tool)
            logger.log(f"✓ {tool} available", "DEBUG")
        else:
            missing_tools.append((tool, install_cmd))
    
    core_available = sum(1 for tool in core_tools if which(tool))
    
    logger.log(f"Security tools available: {len(available_tools)}/{len(tools)}", "INFO")
    logger.log(f"Core tools available: {core_available}/{len(core_tools)}", "INFO")
    
    if missing_tools:
        logger.log("Missing security tools:", "WARNING")
        for tool, install_cmd in missing_tools:
            if tool in core_tools:
                logger.log(f"  \033[91m{tool}\033[0m (CORE): {install_cmd}", "WARNING")
            else:
                logger.log(f"  \033[93m{tool}\033[0m (ENHANCED): {install_cmd}", "WARNING")
        logger.log("Run the install.sh script to automatically install missing tools", "INFO")
    
    return available_tools, missing_tools, core_available

def _check_essential_tools() -> bool:
    """Check essential system tools"""
    essential_tools = ["git", "wget", "unzip", "curl", "dig", "whois"]
    missing_essential = []
    
    for tool in essential_tools:
        if not which(tool):
            missing_essential.append(tool)
    
    if missing_essential:
        logger.log(f"Essential system tools missing: {', '.join(missing_essential)}", "ERROR")
        logger.log("Please install missing system tools using your package manager", "ERROR")
        return False
    
    return True

def validate_dependencies() -> bool:
    """Validate all dependencies and provide helpful error messages"""
    logger.log("Validating dependencies...", "INFO")
    
    # Check Python version
    if not _check_python_version():
        return False
    
    # Check optional Python packages
    _check_python_packages()
    
    # Check security tools
    available_tools, missing_tools, core_available = _check_security_tools()
    
    # Check essential system tools
    if not _check_essential_tools():
        return False
    
    # Check Go installation for tool installation
    if not which("go") and missing_tools:
        logger.log("Go not found but security tools are missing", "WARNING")
        logger.log("Install Go to enable automatic tool installation", "WARNING")
    
    logger.log("Dependency validation completed", "SUCCESS")
    return core_available >= 4  # Require at least 4 core tools

def check_and_setup_environment():
    """Check environment and provide setup guidance if needed"""
    issues_found = []
    
    # Check if we're in the right directory
    script_dir = Path(__file__).resolve().parent
    if not (script_dir / "p4nth30n.cfg.json").exists() and not (script_dir / "targets.txt").exists():
        issues_found.append("Configuration files missing. Run from the correct directory.")
    
    # Check PATH for Go tools
    go_bin_path = Path.home() / "go" / "bin"
    if go_bin_path.exists():
        path_env = os.environ.get("PATH", "")
        if str(go_bin_path) not in path_env:
            issues_found.append(f"Go tools directory not in PATH: {go_bin_path}")
            logger.log(f"Add to PATH: export PATH=\"{go_bin_path}:$PATH\"", "INFO")
    
    # Check write permissions
    try:
        test_file = script_dir / ".write_test"
        test_file.touch()
        test_file.unlink()
    except PermissionError:
        issues_found.append("No write permission in script directory")
    
    if issues_found:
        logger.log("Environment issues found:", "WARNING")
        for issue in issues_found:
            logger.log(f"  - {issue}", "WARNING")
        return False
    
    return True

# ---------- Resource monitor ----------
def get_system_resources() -> Dict[str, float]:
    try:
        import psutil  # type: ignore
        return {
            "cpu": float(psutil.cpu_percent(interval=0.2)),
            "memory": float(psutil.virtual_memory().percent),
            "disk": float(psutil.disk_usage(str(HERE)).percent),
        }
    except Exception:
        # Fallback best-effort (Linux only)
        try:
            cpu_usage = float(subprocess.check_output(
                ["bash", "-lc", "grep 'cpu ' /proc/stat | awk '{u=($2+$4)*100/($2+$4+$5)} END {print u}'"]
            ).decode().strip())
            lines = subprocess.check_output(["free", "-m"]).decode().splitlines()
            total, used = list(map(int, lines[1].split()[1:3]))
            memory_usage = (used / total) * 100
            disk_line = subprocess.check_output(["df", "-h", str(HERE)]).decode().splitlines()[1]
            disk_usage = float(disk_line.split()[4].replace("%", ""))
            return {"cpu": cpu_usage, "memory": memory_usage, "disk": disk_usage}
        except Exception:
            return {"cpu": 0.0, "memory": 0.0, "disk": 0.0}

def resource_monitor(cfg: Dict[str, Any], stop_event: threading.Event):
    """Monitor system resources and throttle when necessary"""
    monitor_interval = cfg.get("resource_management", {}).get("monitor_interval", 5)
    cpu_threshold = cfg.get("resource_management", {}).get("cpu_threshold", 80)
    memory_threshold = cfg.get("resource_management", {}).get("memory_threshold", 80)
    disk_threshold = cfg.get("resource_management", {}).get("disk_threshold", 90)
    
    while not stop_event.is_set():
        try:
            r = get_system_resources()
            if r:  # Only log if we got valid resource data
                logger.log(f"Resources CPU:{r['cpu']:.1f}% MEM:{r['memory']:.1f}% DISK:{r['disk']:.1f}%", "DEBUG")
                
                # Check thresholds and throttle if necessary
                if (r["cpu"] > cpu_threshold or 
                    r["memory"] > memory_threshold or 
                    r["disk"] > disk_threshold):
                    logger.log("High resource usage, throttling operations...", "WARNING")
                    time.sleep(monitor_interval * 2)
                else:
                    time.sleep(monitor_interval)
            else:
                # Fallback if resource monitoring fails
                time.sleep(monitor_interval)
        except Exception as e:
            logger.log(f"Resource monitoring error: {e}", "WARNING")
            time.sleep(monitor_interval)

# ---------- External sources ----------
def git_clone_or_pull(url: str, dest: Path):
    if dest.exists() and (dest / ".git").exists():
        try:
            run_cmd(["git", "-C", str(dest), "pull", "--ff-only"], timeout=600)
            logger.log(f"Updated repo: {url}", "SUCCESS")
            return
        except Exception as e:
            logger.log(f"git pull failed for {url}: {e}, recloning...", "WARNING")
            shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        run_cmd(["git", "clone", "--depth", "1", url, str(dest)], timeout=1200)
        logger.log(f"Cloned repo: {url}", "SUCCESS")
    except Exception as e:
        logger.log(f"git clone failed for {url}: {e}", "ERROR")

def direct_zip_download(url: str, dest: Path):
    # Try both main and master branches for GitHub
    cands = []
    if url.endswith(".git") and "github.com" in url:
        base = url[:-4].replace("github.com", "codeload.github.com")
        cands = [f"{base}/zip/refs/heads/main", f"{base}/zip/refs/heads/master"]
    else:
        cands = [url]
    for u in cands:
        try:
            zip_path = dest.with_suffix(".zip")
            run_cmd(["wget", "-q", "-O", str(zip_path), u], timeout=300, check_return=True)
            extract_path = dest.parent / dest.stem
            extract_path.mkdir(exist_ok=True)
            run_cmd(["unzip", "-o", str(zip_path), "-d", str(extract_path)], timeout=600, check_return=True)
            logger.log(f"Downloaded+extracted {u} -> {extract_path}", "SUCCESS")
            return True
        except Exception as e:
            logger.log(f"Direct download failed {u}: {e}", "WARNING")
    return False

def refresh_external_sources(cfg: Dict[str, Any]) -> Dict[str, Path]:
    sources = {
        "SecLists": EXT_DIR / "SecLists",
        "PayloadsAllTheThings": EXT_DIR / "PayloadsAllTheThings",
        "Exploits": EXPLOITS_DIR / "exploitdb",
        "NucleiTemplates": Path.home() / "nuclei-templates",
        "NucleiCommunity": Path.home() / "nuclei-community",
        "NucleiFuzzing": Path.home() / "nuclei-fuzzing", 
        "CustomNuclei": Path.home() / "custom-nuclei",
        "KnightSec": Path.home() / "nuclei-ksec",
        "Wordlists": EXT_DIR / "Probable-Wordlists",
        "AdditionalWordlists": EXT_DIR / "commonspeak2-wordlists",
        "OneListForAll": EXT_DIR / "OneListForAll",
        "WebDiscoveryWordlists": EXT_DIR / "fuzz.txt",
        "XSSPayloads": PAYLOADS_DIR / "xss-payload-list",
        "SQLIPayloads": PAYLOADS_DIR / "sql-injection-payload-list"
    }
    
    for name, path in sources.items():
        url = cfg["repos"].get(name)
        if not url:
            continue
        git_clone_or_pull(url, path)
        if not path.exists() and cfg["fallback"]["enabled"] and cfg["fallback"]["direct_downloads"]:
            logger.log(f"Trying direct download fallback for {name}", "WARNING")
            direct_zip_download(url, path)
            
    # Special handling for nuclei templates
    if which("nuclei"):
        try:
            logger.log("Updating nuclei templates cache", "INFO")
            run_cmd(["nuclei", "-update-templates"], check_return=False, timeout=300)
        except Exception as e:
            logger.log(f"Failed to update nuclei templates: {e}", "WARNING")
    
    return sources

def get_best_wordlist(category: str) -> Optional[Path]:
    """Get the best available wordlist for a given category"""
    wordlist_mapping = {
        "directories": [
            MERGED_DIR / "directories_merged.txt",
            EXT_DIR / "SecLists" / "Discovery" / "Web-Content" / "directory-list-2.3-medium.txt",
            EXT_DIR / "SecLists" / "Discovery" / "Web-Content" / "common.txt",
            EXT_DIR / "OneListForAll" / "onelistforall.txt",
            EXTRA_DIR / "paths_extra.txt"
        ],
        "files": [
            MERGED_DIR / "files_merged.txt", 
            EXT_DIR / "SecLists" / "Discovery" / "Web-Content" / "raft-medium-files.txt",
            EXT_DIR / "SecLists" / "Discovery" / "Web-Content" / "common.txt",
            EXT_DIR / "fuzz.txt" / "fuzz.txt"
        ],
        "parameters": [
            MERGED_DIR / "params_merged.txt",
            EXT_DIR / "SecLists" / "Discovery" / "Web-Content" / "burp-parameter-names.txt",
            EXTRA_DIR / "params_extra.txt"
        ],
        "subdomains": [
            MERGED_DIR / "subdomains_merged.txt",
            EXT_DIR / "SecLists" / "Discovery" / "DNS" / "subdomains-top1million-110000.txt",
            EXT_DIR / "commonspeak2-wordlists" / "subdomains" / "subdomains.txt"
        ],
        "xss": [
            PAYLOADS_DIR / "xss-payload-list" / "Intruder" / "xss-payload-list.txt",
            EXT_DIR / "PayloadsAllTheThings" / "XSS Injection" / "README.md",
            EXTRA_DIR / "exploit_payloads.txt"
        ],
        "sqli": [
            PAYLOADS_DIR / "sql-injection-payload-list" / "sqli-blind.txt",
            EXT_DIR / "PayloadsAllTheThings" / "SQL Injection" / "README.md",
            EXT_DIR / "SecLists" / "Fuzzing" / "SQLi" / "quick-SQLi.txt"
        ]
    }
    
    wordlists = wordlist_mapping.get(category, [])
    
    for wordlist in wordlists:
        if wordlist.exists() and wordlist.stat().st_size > 0:
            return wordlist
    
    logger.log(f"No wordlist found for category: {category}", "WARNING") 
    return None

def create_enhanced_payloads():
    """Create enhanced payload collections for various attack types"""
    PAYLOADS_DIR.mkdir(exist_ok=True)
    
    # XSS payloads
    xss_payloads_dir = PAYLOADS_DIR / "xss"
    xss_payloads_dir.mkdir(exist_ok=True)
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "';alert('XSS');//",
        "\"><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "'><svg/onload=alert('XSS')>",
        "\"><img/src/onerror=alert('XSS')>",
        "<script>alert(String.fromCharCode(88,83,83))</script>"
    ]
    
    with open(xss_payloads_dir / "basic_xss.txt", 'w') as f:
        f.write('\n'.join(xss_payloads))
    
    # SQLi payloads
    sqli_payloads_dir = PAYLOADS_DIR / "sqli"
    sqli_payloads_dir.mkdir(exist_ok=True)
    
    sqli_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR '1'='1'/*",
        "admin'--",
        "admin'/*",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "') OR ('1'='1'--",
        "') OR ('1'='1'/*",
        "1' OR '1'='1",
        "1' OR '1'='1'--",
        "1' OR '1'='1'/*",
        "1 OR 1=1",
        "1 OR 1=1--",
        "1 OR 1=1/*",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; WAITFOR DELAY '00:00:10'--"
    ]
    
    with open(sqli_payloads_dir / "basic_sqli.txt", 'w') as f:
        f.write('\n'.join(sqli_payloads))
    
    # Nuclei custom payloads
    nuclei_payloads_dir = PAYLOADS_DIR / "nuclei"
    nuclei_payloads_dir.mkdir(exist_ok=True)
    
    # Create custom nuclei template for enhanced testing
    custom_template = """id: enhanced-security-checks
    
info:
  name: Enhanced Security Checks
  author: bl4ckc3ll-pantheon
  severity: info
  
requests:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/wp-admin"
      - "{{BaseURL}}/phpmyadmin"
      
    matchers:
      - type: word
        words:
          - "git"
          - "admin"
          - "phpMyAdmin"
"""
    
    with open(nuclei_payloads_dir / "custom-template.yaml", 'w') as f:
        f.write(custom_template)

def merge_wordlists(seclists_path: Path, payloads_path: Path, probable_wordlists_path: Path, additional_paths: Dict[str, Path] = None):
    """Efficiently merge wordlists with memory optimization"""
    logger.log("Merging wordlists...", "INFO")
    MERGED_DIR.mkdir(parents=True, exist_ok=True)
    
    def _collect_wordlist_files(base_paths: List[Path]) -> List[Path]:
        """Collect wordlist files from base paths"""
        all_files: List[Path] = []
        for base in base_paths:
            if base.exists():
                for root, _, files in os.walk(base):
                    for f in files:
                        if f.endswith((".txt", ".dic", ".lst")):
                            file_path = Path(root) / f
                            # Skip very large files to avoid memory issues
                            try:
                                if file_path.stat().st_size > 100 * 1024 * 1024:  # 100MB limit
                                    logger.log(f"Skipping large file: {file_path}", "WARNING")
                                    continue
                            except OSError:
                                continue
                            all_files.append(file_path)
        return all_files
    
    def _process_wordlist_file(fp: Path, uniq: set, max_lines: int = 100000) -> int:
        """Process a single wordlist file with limits"""
        lines_processed = 0
        try:
            with open(fp, 'r', encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if lines_processed >= max_lines:
                        logger.log(f"Line limit reached for {fp}, stopping", "DEBUG")
                        break
                    
                    s = line.strip()
                    if s and not s.startswith("#") and 3 <= len(s) <= 100:  # Reasonable length limits
                        uniq.add(s)
                        lines_processed += 1
            
            return lines_processed
        except Exception as e:
            logger.log(f"Read error {fp}: {e}", "WARNING")
            return 0
    
    # Collect files from all sources
    base_paths = [seclists_path, payloads_path, probable_wordlists_path, EXTRA_DIR]
    if additional_paths:
        base_paths.extend(additional_paths.values())
    
    all_files = _collect_wordlist_files(base_paths)
    logger.log(f"Found {len(all_files)} wordlist files to process", "INFO")
    
    # Process files with memory management
    uniq = set()
    total_processed = 0
    max_total_lines = 1000000  # 1M line limit to prevent memory issues
    
    for fp in all_files:
        if total_processed >= max_total_lines:
            logger.log(f"Total line limit reached ({max_total_lines}), stopping", "WARNING")
            break
        
        processed = _process_wordlist_file(fp, uniq, max_lines=50000)
        total_processed += processed
        
        # Memory management: if set gets too large, break
        if len(uniq) > 500000:  # 500k unique items limit
            logger.log("Unique items limit reached, stopping merge", "WARNING")
            break
    
    merged_file = MERGED_DIR / "all_merged_wordlist.txt"
    atomic_write(merged_file, "\n".join(sorted(uniq)))
    logger.log(f"Merged {len(uniq)} unique lines from {len(all_files)} files -> {merged_file}", "SUCCESS")

# ---------- Run Management ----------
def new_run() -> Path:
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(uuid.uuid4())[:8]
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    logger.log(f"Created run: {run_dir}", "INFO")
    return run_dir

def env_with_lists() -> Dict[str, str]:
    env = os.environ.copy()
    env["P4NTH30N_MERGED_WORDLISTS"] = str(MERGED_DIR)
    env["P4NTH30N_PAYLOADS"] = str(PAYLOADS_DIR)
    env["P4NTH30N_EXPLOITS"] = str(EXPLOITS_DIR)
    return env

# ---------- Tool wrappers ----------
def run_subfinder(domain: str, out_file: Path, env: Dict[str, str]):
    if not which("subfinder"):
        logger.log("subfinder not found, skipping", "WARNING")
        return
    run_cmd(["subfinder", "-d", domain, "-silent", "-o", str(out_file), "-all"], env=env, timeout=600, check_return=False)

def run_amass(domain: str, out_file: Path, env: Dict[str, str]):
    if not which("amass"):
        logger.log("amass not found, skipping", "WARNING")
        return
    # Passive mode first (faster, lighter)
    run_cmd(["amass", "enum", "-d", domain, "-o", str(out_file), "-passive"], env=env, timeout=1200, check_return=False)

def run_naabu(host: str, out_file: Path, rps: int, env: Dict[str, str]):
    if not which("naabu"):
        logger.log("naabu not found, skipping", "WARNING")
        return
    run_cmd(["naabu", "-host", host, "-p", "-", "-rate", str(rps), "-o", str(out_file), "-silent"], env=env, timeout=1200, check_return=False)

def run_masscan(host: str, out_file: Path, rps: int, env: Dict[str, str]):
    if not which("masscan"):
        logger.log("masscan not found, skipping", "WARNING")
        return
    run_cmd(["masscan", host, "-p", "1-65535", "--rate", str(rps), "-oG", str(out_file)], env=env, timeout=1800, check_return=False)

def run_httpx(input_file: Path, out_file: Path, env: Dict[str, str], http_timeout: int):
    if not which("httpx"):
        logger.log("httpx not found, skipping", "WARNING")
        return
    run_cmd([
        "httpx", "-l", str(input_file), "-o", str(out_file),
        "-silent", "-follow-redirects",
        "-mc", "200,201,202,204,301,302,303,307,308,401,403,405,500",
        "-json", "-title", "-tech-detect", "-sc", "-timeout", str(http_timeout),
        "-server", "-cdn", "-pipeline", "-headers"
    ], env=env, timeout=1200, check_return=False)

def run_gobuster(target: str, wordlist: Path, out_file: Path, extensions: str, env: Dict[str, str]):
    if not which("gobuster"):
        logger.log("gobuster not found, skipping", "WARNING")
        return
    if not wordlist.exists():
        logger.log(f"Wordlist not found: {wordlist}", "WARNING")
        return
    run_cmd([
        "gobuster", "dir", "-u", target, "-w", str(wordlist),
        "-x", extensions, "-o", str(out_file), "-q", "-k", "--no-error"
    ], env=env, timeout=1800, check_return=False)

def run_dirb(target: str, wordlist: Path, out_file: Path, env: Dict[str, str]):
    if not which("dirb"):
        logger.log("dirb not found, skipping", "WARNING")
        return
    if not wordlist.exists():
        logger.log(f"Wordlist not found: {wordlist}", "WARNING")
        return
    run_cmd(["dirb", target, str(wordlist), "-o", str(out_file), "-w"], env=env, timeout=1800, check_return=False)

def run_ffuf(target: str, wordlist: Path, out_file: Path, env: Dict[str, str]):
    if not which("ffuf"):
        logger.log("ffuf not found, skipping", "WARNING")
        return
    if not wordlist.exists():
        logger.log(f"Wordlist not found: {wordlist}", "WARNING")
        return
    target_fuzz = target.rstrip('/') + '/FUZZ'
    run_cmd([
        "ffuf", "-u", target_fuzz, "-w", str(wordlist),
        "-o", str(out_file), "-of", "json", "-mc", "200,201,202,204,301,302,303,307,308,401,403,405",
        "-fs", "0", "-t", "50"
    ], env=env, timeout=1800, check_return=False)

def run_waybackurls(domain: str, out_file: Path, env: Dict[str, str]):
    if not which("waybackurls"):
        logger.log("waybackurls not found, skipping", "WARNING")
        return
    run_cmd(["waybackurls", domain], capture=True, env=env, timeout=600, check_return=False)
    # Redirect output manually
    try:
        result = run_cmd(["waybackurls", domain], capture=True, env=env, timeout=600, check_return=False)
        if result.stdout:
            atomic_write(out_file, result.stdout)
    except Exception as e:
        logger.log(f"waybackurls error: {e}", "WARNING")

def run_gospider(target: str, out_file: Path, depth: int, env: Dict[str, str]):
    if not which("gospider"):
        logger.log("gospider not found, skipping", "WARNING")
        return
    run_cmd([
        "gospider", "-s", target, "-d", str(depth), 
        "-o", str(out_file.parent), "--json", "-t", "10", "-k"
    ], env=env, timeout=900, check_return=False)

def run_whatweb(target: str, out_file: Path, env: Dict[str, str]):
    if not which("whatweb"):
        logger.log("whatweb not found, skipping", "WARNING")
        return
    run_cmd([
        "whatweb", target, "--log-json", str(out_file),
        "-a", "3", "--max-threads", "10"
    ], env=env, timeout=600, check_return=False)

def run_nikto(target: str, out_file: Path, env: Dict[str, str]):
    if not which("nikto"):
        logger.log("nikto not found, skipping", "WARNING")
        return
    run_cmd([
        "nikto", "-h", target, "-output", str(out_file),
        "-Format", "json", "-Timeout", "10"
    ], env=env, timeout=1800, check_return=False)

def run_subjack(subdomains_file: Path, out_file: Path, env: Dict[str, str]):
    if not which("subjack"):
        logger.log("subjack not found, skipping", "WARNING")
        return
    if not subdomains_file.exists():
        logger.log(f"Subdomains file not found: {subdomains_file}", "WARNING")
        return
    run_cmd([
        "subjack", "-w", str(subdomains_file), "-o", str(out_file),
        "-c", "/opt/subjack/fingerprints.json", "-v"
    ], env=env, timeout=600, check_return=False)

def run_sqlmap(target: str, out_file: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    if not which("sqlmap"):
        logger.log("sqlmap not found, skipping", "WARNING")
        return
    
    # Get configuration
    sqlmap_cfg = cfg.get("sqlmap_testing", {})
    
    cmd = [
        "sqlmap", "-u", target, "--batch", 
        "--crawl", str(sqlmap_cfg.get("crawl_depth", 1)),  # Reduced crawl depth
        "--level", str(sqlmap_cfg.get("level", 2)),        # Reduced level 
        "--risk", str(sqlmap_cfg.get("risk", 2)), 
        "--output-dir", str(out_file.parent),
        "--technique", sqlmap_cfg.get("techniques", "BEUST"),
        "--threads", str(sqlmap_cfg.get("threads", 2)),    # Reduced threads
        "--timeout", "30",                                 # Add timeout
        "--retries", "1"                                   # Reduce retries
    ]
    
    # Add tamper scripts if configured
    tamper_scripts = sqlmap_cfg.get("tamper_scripts", [])
    if tamper_scripts:
        cmd.extend(["--tamper", ",".join(tamper_scripts)])
    
    # Reduced overall timeout to prevent hanging
    run_cmd(cmd, env=env, timeout=600, check_return=False)

def run_additional_sql_tests(target: str, out_file: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Run additional SQL injection tests using custom payloads"""
    logger.log(f"Running additional SQL tests for {target}", "DEBUG")
    
    sql_results = {
        "target": target,
        "basic_tests": [],
        "timestamp": datetime.now().isoformat()
    }
    
    # Basic SQL error detection payloads
    test_payloads = [
        "'", "''", "1'", "1' OR '1'='1", "admin'--", 
        "' OR 1=1--", "' UNION SELECT NULL--", "1; WAITFOR DELAY '00:00:05'--"
    ]
    
    try:
        for payload in test_payloads[:5]:  # Limit to avoid excessive testing
            test_url = f"{target}?id={payload}"
            
            try:
                # Simple test with curl
                result = run_cmd([
                    "curl", "-s", "-m", "8", "-L", "--max-redirs", "3", test_url
                ], capture=True, timeout=10, check_return=False)
                
                if result.stdout:
                    # Look for SQL error patterns
                    error_patterns = [
                        "mysql_fetch", "ora-01", "microsoft ole db", "syntax error",
                        "sqlstate", "postgresql", "warning: mysql"
                    ]
                    
                    response_text = result.stdout.lower()
                    for pattern in error_patterns:
                        if pattern in response_text:
                            sql_results["basic_tests"].append({
                                "payload": payload,
                                "error_pattern": pattern,
                                "potential_sqli": True
                            })
                            break
            except Exception as e:
                logger.log(f"Error testing SQL payload {payload}: {e}", "DEBUG")
        
        atomic_write(out_file, json.dumps(sql_results, indent=2))
        
    except Exception as e:
        logger.log(f"Error in additional SQL tests: {e}", "WARNING")

def run_xss_strike(target: str, out_file: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Run XSStrike for XSS vulnerability testing"""
    # Check multiple possible command names for XSStrike
    xss_strike_cmd = None
    for cmd_name in ["xsstrike", "xssstrike", "XSStrike.py"]:
        if which(cmd_name):
            xss_strike_cmd = cmd_name
            break
    
    if not xss_strike_cmd:
        logger.log("XSStrike not found (tried: xsstrike, xssstrike, XSStrike.py), skipping", "WARNING")
        return
    
    xss_cfg = cfg.get("xss_testing", {})
    
    cmd = [xss_strike_cmd, "-u", target]
    
    if xss_cfg.get("reflected_xss", True):
        cmd.append("--fuzzer")
    
    if xss_cfg.get("crawl", True):
        cmd.extend(["--crawl", "--level", "2"])
    
    # Output to file
    result_file = out_file.parent / f"xsstrike_{target.replace('/', '_').replace(':', '_')}.json"
    cmd.extend(["-o", str(result_file)])
    
    run_cmd(cmd, env=env, timeout=1200, check_return=False)

def run_dalfox(target: str, out_file: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Run Dalfox for XSS vulnerability testing"""
    if not which("dalfox"):
        logger.log("Dalfox not found, skipping", "WARNING")
        return
    
    xss_cfg = cfg.get("xss_testing", {})
    
    cmd = [
        "dalfox", "url", target,
        "--format", "json",
        "--output", str(out_file),
        "--timeout", "10"
    ]
    
    # Add crawling if enabled
    if xss_cfg.get("crawl", True):
        cmd.extend(["--crawl", "--crawl-depth", "2"])
    
    # Add blind XSS if enabled  
    if xss_cfg.get("blind_xss", True):
        cmd.append("--blind")
    
    run_cmd(cmd, env=env, timeout=600, check_return=False)

def run_subzy(targets_file: Path, out_file: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Run Subzy for subdomain takeover detection"""
    if not which("subzy"):
        logger.log("subzy not found, skipping", "WARNING")
        return
    
    takeover_cfg = cfg.get("subdomain_takeover", {})
    
    cmd = [
        "subzy", "run",
        "--targets", str(targets_file),
        "--concurrency", str(takeover_cfg.get("threads", 10)),
        "--timeout", str(takeover_cfg.get("timeout", 30)),
        "--verify_ssl"
    ]
    
    # Run and capture output
    try:
        result = run_cmd(cmd, env=env, timeout=600, capture=True, check_return=False)
        if result.stdout:
            with open(out_file, 'w') as f:
                f.write(result.stdout)
    except Exception as e:
        logger.log(f"Subzy execution error: {e}", "ERROR")

def run_enhanced_nmap(target: str, out_file: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Run enhanced Nmap scanning with advanced options"""
    if not which("nmap"):
        logger.log("nmap not found, skipping", "WARNING")
        return
        
    nmap_cfg = cfg.get("nmap_scanning", {})
    hostname = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Basic service detection
    if nmap_cfg.get("service_detection", True):
        cmd = [
            "nmap", "-sS", "-sV", 
            "--top-ports", str(nmap_cfg.get("top_ports", 1000)),
            "-T" + str(nmap_cfg.get("timing", 4)),
            "-oA", str(out_file.parent / f"nmap_{hostname}"),
            hostname
        ]
        
        if nmap_cfg.get("os_detection", True):
            cmd.insert(-1, "-O")
            
        if nmap_cfg.get("script_scanning", True):
            cmd.insert(-1, "-sC")
            
        run_cmd(cmd, env=env, timeout=1800, check_return=False)
    
    # Vulnerability scripts
    if nmap_cfg.get("vulnerability_scripts", True):
        vuln_cmd = [
            "nmap", "--script", "vuln",
            "--script-args", "unsafe=1",
            "-oA", str(out_file.parent / f"nmap_vuln_{hostname}"),
            hostname
        ]
        run_cmd(vuln_cmd, env=env, timeout=2400, check_return=False)

def run_feroxbuster(target: str, wordlist: Path, out_file: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Run feroxbuster for directory discovery"""
    if not which("feroxbuster"):
        logger.log("feroxbuster not found, skipping", "WARNING")
        return
    if not wordlist.exists():
        logger.log(f"Wordlist not found: {wordlist}", "WARNING")
        return
        
    fuzzing_cfg = cfg.get("fuzzing", {})
    
    cmd = [
        "feroxbuster", 
        "-u", target,
        "-w", str(wordlist),
        "-o", str(out_file),
        "-t", str(fuzzing_cfg.get("threads", 50)),
        "-s", fuzzing_cfg.get("status_codes", "200,204,301,302,307,308,401,403,405,500"),
        "--auto-tune"
    ]
    
    # Add extensions if configured
    extensions = fuzzing_cfg.get("extensions", "")
    if extensions:
        cmd.extend(["-x", extensions])
    
    # Recursive scanning if enabled
    if fuzzing_cfg.get("recursive_fuzzing", True):
        cmd.extend(["-r", "-d", "3"])
    
    run_cmd(cmd, env=env, timeout=1800, check_return=False)

def run_nuclei_single_target(target: str, out_file: Path, cfg: Dict[str, Any], env: Dict[str, str]):
    if not which("nuclei") or not cfg["nuclei"]["enabled"]:
        logger.log("nuclei not found or disabled, skipping", "WARNING")
        return
        
    nuclei_cfg = cfg["nuclei"]
    
    cmd = [
        "nuclei", "-u", target, "-json", "-o", str(out_file),
        "-severity", nuclei_cfg["severity"],
        "-rl", str(nuclei_cfg["rps"]),
        "-c", str(nuclei_cfg["conc"]),
        "-silent", "-no-color"
    ]
    
    # Add community template sources
    if nuclei_cfg.get("community_templates", True):
        template_sources = nuclei_cfg.get("template_sources", [])
        for template_source in template_sources:
            template_path = Path(template_source).expanduser()
            if template_path.exists():
                cmd.extend(["-t", str(template_path)])
    
    if nuclei_cfg["all_templates"]:
        # default template path commonly at ~/nuclei-templates
        tpl = str(Path.home() / "nuclei-templates")
        if Path(tpl).exists():
            cmd.extend(["-t", tpl])
    
    # Add custom templates if enabled
    if nuclei_cfg.get("custom_templates", False):
        custom_templates = PLUGINS_DIR / "nuclei_templates"
        if custom_templates.exists():
            cmd.extend(["-t", str(custom_templates)])
    
    # Custom template categories
    template_categories = nuclei_cfg.get("template_categories", "all")
    if template_categories != "all":
        cmd.extend(["-tags", template_categories])
    
    # Exclude templates if configured
    exclude_templates = nuclei_cfg.get("exclude_templates", [])
    if exclude_templates:
        for exclude in exclude_templates:
            cmd.extend(["-exclude-tags", exclude])
    
    run_cmd(cmd, env=env, timeout=3600, check_return=False)

def run_dns_enumeration(domain: str, out_file: Path, env: Dict[str, str]):
    """Enhanced DNS enumeration with multiple record types"""
    dns_info = {
        "domain": domain,
        "records": {},
        "nameservers": [],
        "mx_records": [],
        "txt_records": []
    }
    
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR"]
    
    for record_type in record_types:
        try:
            result = run_cmd(["dig", "+short", record_type, domain], capture=True, timeout=30, check_return=False)
            if result.stdout and result.stdout.strip():
                dns_info["records"][record_type] = result.stdout.strip().split('\n')
        except Exception as e:
            logger.log(f"DNS lookup error for {record_type} {domain}: {e}", "DEBUG")
    
    atomic_write(out_file, json.dumps(dns_info, indent=2))

def run_ssl_analysis(target: str, out_file: Path, env: Dict[str, str]):
    """SSL/TLS certificate analysis"""
    if not target.startswith("https://"):
        target = f"https://{target}"
    
    ssl_info = {
        "target": target,
        "certificate": {},
        "ciphers": [],
        "protocols": []
    }
    
    try:
        # Use openssl to get certificate info
        hostname = target.replace("https://", "").split("/")[0]
        result = run_cmd([
            "openssl", "s_client", "-connect", f"{hostname}:443",
            "-servername", hostname, "-showcerts"
        ], capture=True, timeout=30, check_return=False, use_shell=False)
        
        if result.stdout:
            ssl_info["raw_output"] = result.stdout
            
        atomic_write(out_file, json.dumps(ssl_info, indent=2))
    except Exception as e:
        logger.log(f"SSL analysis error for {target}: {e}", "WARNING")

def run_network_analysis(target: str, out_dir: Path, env: Dict[str, str]):
    """Comprehensive network analysis"""
    out_dir.mkdir(exist_ok=True)
    
    # Clean hostname from target
    hostname = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Whois lookup
    if which("whois"):
        try:
            result = run_cmd(["whois", hostname], capture=True, timeout=60, check_return=False)
            if result.stdout:
                atomic_write(out_dir / "whois.txt", result.stdout)
        except Exception as e:
            logger.log(f"Whois error for {hostname}: {e}", "WARNING")
    
    # Traceroute
    if which("traceroute"):
        try:
            result = run_cmd(["traceroute", "-m", "15", hostname], capture=True, timeout=120, check_return=False)
            if result.stdout:
                atomic_write(out_dir / "traceroute.txt", result.stdout)
        except Exception as e:
            logger.log(f"Traceroute error for {hostname}: {e}", "WARNING")
    
    # ASN lookup using dig
    try:
        result = run_cmd(["dig", "+short", hostname], capture=True, timeout=30, check_return=False)
        if result.stdout:
            ip = result.stdout.strip().split('\n')[0]
            if ip:
                # Reverse IP for ASN lookup
                reversed_ip = '.'.join(ip.split('.')[::-1])
                asn_result = run_cmd(["dig", "+short", f"{reversed_ip}.origin.asn.cymru.com", "TXT"], 
                                   capture=True, timeout=30, check_return=False)
                if asn_result.stdout:
                    atomic_write(out_dir / "asn_info.txt", f"IP: {ip}\nASN: {asn_result.stdout}")
    except Exception as e:
        logger.log(f"ASN lookup error for {hostname}: {e}", "WARNING")

def run_api_discovery(target: str, out_file: Path, env: Dict[str, str]):
    """Enhanced API endpoint discovery and analysis"""
    try:
        logger.log(f"API discovery for {target}", "INFO")
        results = []
        
        # Common API endpoints
        api_endpoints = [
            "/api", "/api/v1", "/api/v2", "/rest", "/graphql", 
            "/swagger", "/swagger.json", "/openapi.json", "/api-docs",
            "/docs", "/documentation", "/spec", "/.well-known",
            "/health", "/status", "/metrics", "/admin"
        ]
        
        for endpoint in api_endpoints:
            try:
                if which("curl"):
                    test_url = f"{target.rstrip('/')}{endpoint}"
                    result = run_cmd(["curl", "-s", "-I", "-L", "--max-time", "10", test_url], 
                                   capture=True, timeout=15, check_return=False)
                    if result.stdout and ("200" in result.stdout or "swagger" in result.stdout.lower() or "api" in result.stdout.lower()):
                        results.append({
                            "endpoint": endpoint,
                            "url": test_url,
                            "response_headers": result.stdout.strip(),
                            "discovered": datetime.now().isoformat()
                        })
            except Exception:
                continue
        
        # Save results
        atomic_write(out_file, json.dumps(results, indent=2))
        logger.log(f"Found {len(results)} potential API endpoints", "SUCCESS")
        
    except Exception as e:
        logger.log(f"API discovery error: {e}", "ERROR")

def run_graphql_testing(target: str, out_file: Path, env: Dict[str, str]):
    """GraphQL security testing"""
    try:
        logger.log(f"GraphQL testing for {target}", "INFO")
        results = {}
        
        graphql_endpoints = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"]
        
        for endpoint in graphql_endpoints:
            try:
                if which("curl"):
                    test_url = f"{target.rstrip('/')}{endpoint}"
                    
                    # Test for introspection
                    introspection_query = {"query": "{ __schema { types { name } } }"}
                    result = run_cmd([
                        "curl", "-s", "-X", "POST", 
                        "-H", "Content-Type: application/json",
                        "-d", json.dumps(introspection_query),
                        "--max-time", "10", test_url
                    ], capture=True, timeout=15, check_return=False)
                    
                    if result.stdout and ("__schema" in result.stdout or "types" in result.stdout):
                        results[endpoint] = {
                            "introspection_enabled": True,
                            "response": result.stdout.strip(),
                            "url": test_url
                        }
                    
                    # Test for common GraphQL vulnerabilities
                    test_queries = [
                        '{ __type(name: "User") { fields { name type { name } } } }',
                        'query { users { id email password } }'
                    ]
                    
                    for query in test_queries:
                        test_query = {"query": query}
                        result = run_cmd([
                            "curl", "-s", "-X", "POST",
                            "-H", "Content-Type: application/json", 
                            "-d", json.dumps(test_query),
                            "--max-time", "5", test_url
                        ], capture=True, timeout=10, check_return=False)
                        
                        if result.stdout and "data" in result.stdout:
                            if endpoint not in results:
                                results[endpoint] = {}
                            results[endpoint]["vulnerable_queries"] = results[endpoint].get("vulnerable_queries", [])
                            results[endpoint]["vulnerable_queries"].append({
                                "query": query,
                                "response": result.stdout.strip()
                            })
                            
            except Exception:
                continue
        
        atomic_write(out_file, json.dumps(results, indent=2))
        logger.log(f"GraphQL testing completed, found {len(results)} endpoints", "SUCCESS")
        
    except Exception as e:
        logger.log(f"GraphQL testing error: {e}", "ERROR")

def run_jwt_analysis(target: str, out_file: Path, env: Dict[str, str]):
    """JWT token analysis and security testing"""
    try:
        logger.log(f"JWT analysis for {target}", "INFO")
        results = {}
        
        if which("curl"):
            # Look for JWT tokens in common locations
            test_endpoints = ["/login", "/auth", "/token", "/api/auth", "/oauth"]
            
            for endpoint in test_endpoints:
                try:
                    test_url = f"{target.rstrip('/')}{endpoint}"
                    result = run_cmd(["curl", "-s", "-I", "--max-time", "10", test_url], 
                                   capture=True, timeout=15, check_return=False)
                    
                    if result.stdout and ("bearer" in result.stdout.lower() or "jwt" in result.stdout.lower()):
                        results[endpoint] = {
                            "jwt_detected": True,
                            "headers": result.stdout.strip(),
                            "url": test_url
                        }
                        
                        # Test for common JWT vulnerabilities
                        jwt_tests = [
                            {"name": "None Algorithm", "header": '{"alg": "none", "typ": "JWT"}'},
                            {"name": "Weak Secret", "test": "weak_secret_test"},
                            {"name": "Key Confusion", "test": "key_confusion_test"}
                        ]
                        
                        results[endpoint]["vulnerability_tests"] = jwt_tests
                        
                except Exception:
                    continue
        
        atomic_write(out_file, json.dumps(results, indent=2))
        logger.log(f"JWT analysis completed", "SUCCESS")
        
    except Exception as e:
        logger.log(f"JWT analysis error: {e}", "ERROR")

def run_cloud_storage_scanning(target: str, out_file: Path, env: Dict[str, str]):
    """Scan for exposed cloud storage buckets and containers"""
    try:
        logger.log(f"Cloud storage scanning for {target}", "INFO")
        results = {}
        
        # Extract domain for bucket name generation
        from urllib.parse import urlparse
        parsed = urlparse(target if target.startswith('http') else f"http://{target}")
        domain = parsed.netloc or target
        base_name = domain.replace('.', '-').replace('_', '-')
        
        # Generate potential bucket names
        bucket_names = [
            base_name, f"{base_name}-backup", f"{base_name}-data", f"{base_name}-files",
            f"{base_name}-images", f"{base_name}-static", f"{base_name}-assets",
            f"{base_name}-dev", f"{base_name}-prod", f"{base_name}-test"
        ]
        
        # AWS S3 buckets
        for bucket in bucket_names:
            try:
                if which("curl"):
                    s3_url = f"https://{bucket}.s3.amazonaws.com/"
                    result = run_cmd(["curl", "-s", "-I", "--max-time", "10", s3_url],
                                   capture=True, timeout=15, check_return=False)
                    
                    if result.stdout and ("200" in result.stdout or "403" in result.stdout):
                        results[f"s3_{bucket}"] = {
                            "type": "AWS S3",
                            "url": s3_url,
                            "status": "accessible" if "200" in result.stdout else "exists_but_protected",
                            "headers": result.stdout.strip()
                        }
            except Exception:
                continue
        
        # Azure Storage
        for bucket in bucket_names:
            try:
                if which("curl"):
                    azure_url = f"https://{bucket}.blob.core.windows.net/"
                    result = run_cmd(["curl", "-s", "-I", "--max-time", "10", azure_url],
                                   capture=True, timeout=15, check_return=False)
                    
                    if result.stdout and ("200" in result.stdout or "400" in result.stdout):
                        results[f"azure_{bucket}"] = {
                            "type": "Azure Blob",
                            "url": azure_url,
                            "status": "accessible" if "200" in result.stdout else "exists",
                            "headers": result.stdout.strip()
                        }
            except Exception:
                continue
        
        # Google Cloud Storage
        for bucket in bucket_names:
            try:
                if which("curl"):
                    gcs_url = f"https://storage.googleapis.com/{bucket}/"
                    result = run_cmd(["curl", "-s", "-I", "--max-time", "10", gcs_url],
                                   capture=True, timeout=15, check_return=False)
                    
                    if result.stdout and ("200" in result.stdout or "403" in result.stdout):
                        results[f"gcs_{bucket}"] = {
                            "type": "Google Cloud Storage",
                            "url": gcs_url,
                            "status": "accessible" if "200" in result.stdout else "exists_but_protected",
                            "headers": result.stdout.strip()
                        }
            except Exception:
                continue
        
        atomic_write(out_file, json.dumps(results, indent=2))
        logger.log(f"Found {len(results)} cloud storage resources", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Cloud storage scanning error: {e}", "ERROR")

def run_threat_intelligence_lookup(target: str, out_file: Path, cfg: Dict[str, Any], env: Dict[str, str]):
    """Perform threat intelligence lookups using various sources"""
    try:
        logger.log(f"Threat intelligence lookup for {target}", "INFO")
        results = {}
        
        # Extract domain/IP
        from urllib.parse import urlparse
        parsed = urlparse(target if target.startswith('http') else f"http://{target}")
        domain = parsed.netloc or target
        
        # Shodan lookup (if API key provided)
        shodan_api = cfg.get("threat_intelligence", {}).get("shodan_api", "")
        if shodan_api and which("curl"):
            try:
                shodan_url = f"https://api.shodan.io/host/{domain}?key={shodan_api}"
                result = run_cmd(["curl", "-s", "--max-time", "15", shodan_url],
                               capture=True, timeout=20, check_return=False)
                
                if result.stdout and "error" not in result.stdout.lower():
                    results["shodan"] = json.loads(result.stdout)
            except Exception:
                pass
        
        # VirusTotal lookup (if API key provided)
        vt_api = cfg.get("threat_intelligence", {}).get("virustotal_api", "")
        if vt_api and which("curl"):
            try:
                vt_url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                result = run_cmd([
                    "curl", "-s", "--max-time", "15",
                    "-d", f"apikey={vt_api}",
                    "-d", f"domain={domain}",
                    vt_url
                ], capture=True, timeout=20, check_return=False)
                
                if result.stdout:
                    try:
                        vt_data = json.loads(result.stdout)
                        if vt_data.get("response_code") == 1:
                            results["virustotal"] = vt_data
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.error(f"Failed to parse VirusTotal JSON response: {e}")
                        pass
            except Exception:
                pass
        
        # Check against common threat feeds (passive)
        try:
            if which("dig"):
                # Check if domain is in abuse.ch feeds
                abuse_result = run_cmd(["dig", "+short", f"{domain}.abuse.ch"],
                                     capture=True, timeout=10, check_return=False)
                if abuse_result.stdout and abuse_result.stdout.strip():
                    results["abuse_ch"] = {
                        "listed": True,
                        "response": abuse_result.stdout.strip()
                    }
        except Exception:
            pass
        
        atomic_write(out_file, json.dumps(results, indent=2))
        logger.log(f"Threat intelligence lookup completed", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Threat intelligence lookup error: {e}", "ERROR")

def run_compliance_checks(target: str, out_file: Path, cfg: Dict[str, Any], env: Dict[str, str]):
    """Run compliance-specific security checks"""
    try:
        logger.log(f"Compliance checks for {target}", "INFO")
        results = {}
        
        compliance_cfg = cfg.get("compliance", {})
        
        if compliance_cfg.get("owasp_top10", True):
            results["owasp_top10"] = {
                "injection": [],
                "broken_auth": [],
                "sensitive_data": [],
                "xxe": [],
                "broken_access": [],
                "security_config": [],
                "xss": [],
                "insecure_deserialization": [],
                "vulnerable_components": [],
                "logging_monitoring": []
            }
            
            # Basic OWASP Top 10 checks
            if which("curl"):
                # SQL Injection basic test
                sql_payloads = ["'", "1' OR '1'='1", "admin'--"]
                for payload in sql_payloads:
                    try:
                        test_url = f"{target}?id={payload}"
                        result = run_cmd(["curl", "-s", "--max-time", "10", test_url],
                                       capture=True, timeout=15, check_return=False)
                        if result.stdout and ("error" in result.stdout.lower() or "sql" in result.stdout.lower()):
                            results["owasp_top10"]["injection"].append({
                                "payload": payload,
                                "response_indicates_vulnerability": True
                            })
                    except Exception:
                        continue
                
                # XSS basic test
                xss_payloads = ["<script>alert('xss')</script>", "javascript:alert('xss')"]
                for payload in xss_payloads:
                    try:
                        test_url = f"{target}?search={payload}"
                        result = run_cmd(["curl", "-s", "--max-time", "10", test_url],
                                       capture=True, timeout=15, check_return=False)
                        if result.stdout and payload in result.stdout:
                            results["owasp_top10"]["xss"].append({
                                "payload": payload,
                                "reflected": True
                            })
                    except Exception:
                        continue
        
        if compliance_cfg.get("pci_dss", True):
            results["pci_dss"] = {
                "ssl_tls_version": {},
                "secure_protocols": {},
                "encryption_strength": {}
            }
            
            # Check SSL/TLS configuration for PCI DSS compliance
            if which("openssl"):
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(target if target.startswith('http') else f"https://{target}")
                    host = parsed.netloc or target
                    port = parsed.port or 443
                    
                    # Test TLS versions
                    tls_versions = ["ssl3", "tls1", "tls1_1", "tls1_2", "tls1_3"]
                    for version in tls_versions:
                        result = run_cmd([
                            "openssl", "s_client", f"-{version}",
                            "-connect", f"{host}:{port}",
                            "-servername", host
                        ], input_data="", capture=True, timeout=10, check_return=False)
                        
                        if result.stdout:
                            if "Verify return code: 0" in result.stdout:
                                results["pci_dss"]["ssl_tls_version"][version] = "supported"
                            else:
                                results["pci_dss"]["ssl_tls_version"][version] = "not_supported"
                except Exception:
                    pass
        
        atomic_write(out_file, json.dumps(results, indent=2))
        logger.log(f"Compliance checks completed", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Compliance checks error: {e}", "ERROR")

def run_ml_vulnerability_analysis(scan_results_dir: Path, out_file: Path, cfg: Dict[str, Any]):
    """Apply machine learning-based analysis to scan results"""
    try:
        logger.log("ML-based vulnerability analysis starting", "INFO")
        results = {
            "false_positive_reduction": {},
            "risk_scoring": {},
            "pattern_analysis": {},
            "prioritization": []
        }
        
        ml_cfg = cfg.get("ml_analysis", {})
        
        if ml_cfg.get("false_positive_reduction", True):
            # Simple heuristic-based false positive reduction
            nuclei_results = []
            for nuclei_file in scan_results_dir.glob("**/nuclei_results.jsonl"):
                try:
                    with open(nuclei_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                nuclei_results.append(json.loads(line))
                except Exception:
                    continue
            
            # Basic false positive filtering
            filtered_results = []
            for result in nuclei_results:
                confidence_score = 1.0
                
                # Reduce confidence for common false positives
                if result.get("template-id", "").startswith("tech-detect"):
                    confidence_score *= 0.3
                elif "info" in result.get("info", {}).get("severity", "").lower():
                    confidence_score *= 0.5
                elif "exposed" in result.get("template-id", "").lower():
                    confidence_score *= 0.7
                
                # Increase confidence for critical findings
                if "critical" in result.get("info", {}).get("severity", "").lower():
                    confidence_score *= 1.5
                elif "rce" in result.get("template-id", "").lower():
                    confidence_score *= 1.8
                elif "sqli" in result.get("template-id", "").lower():
                    confidence_score *= 1.6
                
                result["confidence_score"] = min(confidence_score, 1.0)
                if confidence_score > 0.4:  # Threshold for inclusion
                    filtered_results.append(result)
            
            results["false_positive_reduction"] = {
                "original_count": len(nuclei_results),
                "filtered_count": len(filtered_results),
                "reduction_percentage": ((len(nuclei_results) - len(filtered_results)) / max(len(nuclei_results), 1)) * 100
            }
        
        if ml_cfg.get("risk_scoring_ml", True):
            # Calculate risk scores based on multiple factors
            risk_factors = {}
            
            # Count vulnerabilities by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for result in nuclei_results:
                severity = result.get("info", {}).get("severity", "info").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Calculate weighted risk score
            weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0.5}
            total_score = sum(severity_counts[sev] * weights[sev] for sev in severity_counts)
            
            results["risk_scoring"] = {
                "total_risk_score": total_score,
                "severity_distribution": severity_counts,
                "risk_level": "critical" if total_score > 50 else "high" if total_score > 20 else "medium" if total_score > 5 else "low"
            }
        
        atomic_write(out_file, json.dumps(results, indent=2))
        logger.log("ML vulnerability analysis completed", "SUCCESS")
        
    except Exception as e:
        logger.log(f"ML vulnerability analysis error: {e}", "ERROR")

# ---------- Core stages ----------
def stage_recon(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    logger.log("Enhanced recon stage started", "INFO")
    recon_dir = run_dir / "recon"
    recon_dir.mkdir(exist_ok=True)
    targets = read_lines(TARGETS)
    if not targets:
        logger.log("No targets, skipping recon", "WARNING")
        return

    def per_target(target: str) -> Dict[str, Any]:
        tdir = recon_dir / target.replace(".", "_").replace("/", "_")
        tdir.mkdir(exist_ok=True)
        results: Dict[str, Any] = {
            "target": target, 
            "status": "failed", 
            "subdomains": [], 
            "open_ports": [], 
            "http_info": [],
            "technology_stack": [],
            "ssl_info": {},
            "network_info": {},
            "directories": [],
            "endpoints": []
        }
        
        try:
            host = target
            if host.startswith("http://") or host.startswith("https://"):
                host = host.split("://", 1)[1].split("/", 1)[0]
            
            logger.log(f"Starting recon for {target}", "INFO")
            
            # Phase 1: Subdomain Discovery
            logger.log(f"Phase 1: Subdomain discovery for {host}", "INFO")
            subfinder_out = tdir / "subfinder_subs.txt"
            amass_out = tdir / "amass_subs.txt"
            merged_subs = tdir / "subdomains.txt"

            run_subfinder(host, subfinder_out, env)
            run_amass(host, amass_out, env)

            subs = set()
            for p in [subfinder_out, amass_out]:
                if p.exists():
                    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                        s = line.strip()
                        if s and not s.startswith("#"):
                            subs.add(s)
            
            # Add the main domain if not in subdomain list
            if host not in subs:
                subs.add(host)
                
            atomic_write(merged_subs, "\n".join(sorted(subs)))
            results["subdomains"] = sorted(subs)
            logger.log(f"{target}: {len(subs)} subdomains discovered", "INFO")

            # Phase 2: DNS Enumeration
            if cfg["advanced_scanning"]["dns_enumeration"]:
                logger.log(f"Phase 2: DNS enumeration for {host}", "INFO")
                dns_out = tdir / "dns_info.json"
                run_dns_enumeration(host, dns_out, env)
                if dns_out.exists():
                    try:
                        results["dns_info"] = json.loads(dns_out.read_text())
                    except Exception:
                        pass

            # Phase 3: Port Discovery (Enhanced)
            logger.log(f"Phase 3: Port discovery for {host}", "INFO")
            ports_out = tdir / "open_ports.txt"
            masscan_out = tdir / "masscan_ports.txt"
            
            # Use both naabu and masscan if available
            run_naabu(host, ports_out, cfg["limits"]["rps"], env)
            if cfg["limits"]["rps"] > 1000:  # Only use masscan for high-speed scans
                run_masscan(host, masscan_out, min(cfg["limits"]["rps"], 5000), env)
            
            oports: List[Dict[str, Any]] = []
            
            # Parse naabu output
            if ports_out.exists():
                for line in ports_out.read_text(encoding="utf-8", errors="ignore").splitlines():
                    l = line.strip()
                    if l and ":" in l:
                        try:
                            h, port = l.rsplit(":", 1)
                            oports.append({"host": h, "port": int(port), "proto": "tcp", "source": "naabu"})
                        except Exception:
                            pass
            
            # Parse masscan output
            if masscan_out.exists():
                for line in masscan_out.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if "open" in line and "tcp" in line:
                        try:
                            parts = line.split()
                            for part in parts:
                                if "/" in part and part.split("/")[1] == "tcp":
                                    port = int(part.split("/")[0])
                                    oports.append({"host": host, "port": port, "proto": "tcp", "source": "masscan"})
                                    break
                        except Exception:
                            pass
            
            # Deduplicate ports
            unique_ports = {}
            for port_info in oports:
                key = f"{port_info['host']}:{port_info['port']}"
                if key not in unique_ports:
                    unique_ports[key] = port_info
            
            results["open_ports"] = list(unique_ports.values())
            logger.log(f"{target}: {len(results['open_ports'])} unique open ports", "INFO")

            # Phase 4: HTTP Service Discovery
            logger.log(f"Phase 4: HTTP service discovery for {target}", "INFO")
            httpx_in = tdir / "httpx_input.txt"
            httpx_out = tdir / "httpx_output.jsonl"
            
            if subs:
                atomic_write(httpx_in, "\n".join(sorted(subs)))
                run_httpx(httpx_in, httpx_out, env, cfg["limits"]["http_timeout"])
                if httpx_out.exists():
                    http_info: List[Dict[str, Any]] = []
                    for line in httpx_out.read_text(encoding="utf-8", errors="ignore").splitlines():
                        try:
                            data = json.loads(line)
                            http_info.append(data)
                        except Exception:
                            pass
                    results["http_info"] = http_info

            # Phase 5: Technology Detection
            if cfg["advanced_scanning"]["technology_detection"]:
                logger.log(f"Phase 5: Technology detection for {target}", "INFO")
                whatweb_out = tdir / "whatweb.json"
                run_whatweb(target if target.startswith("http") else f"http://{target}", whatweb_out, env)
                if whatweb_out.exists():
                    try:
                        tech_data = json.loads(whatweb_out.read_text())
                        results["technology_stack"] = tech_data
                    except Exception:
                        pass

            # Phase 6: SSL Analysis
            if cfg["advanced_scanning"]["ssl_analysis"]:
                logger.log(f"Phase 6: SSL analysis for {target}", "INFO")
                ssl_out = tdir / "ssl_analysis.json"
                run_ssl_analysis(target if target.startswith("https") else f"https://{target}", ssl_out, env)
                if ssl_out.exists():
                    try:
                        results["ssl_info"] = json.loads(ssl_out.read_text())
                    except Exception:
                        pass

            # Phase 7: Network Analysis
            if cfg["network_analysis"]["whois_lookup"]:
                logger.log(f"Phase 7: Network analysis for {target}", "INFO")
                network_dir = tdir / "network_analysis"
                run_network_analysis(target, network_dir, env)
                if network_dir.exists():
                    network_info = {}
                    for file in network_dir.glob("*.txt"):
                        try:
                            network_info[file.stem] = file.read_text()
                        except Exception:
                            pass
                    results["network_info"] = network_info

            # Phase 8: Directory/File Fuzzing
            if cfg["fuzzing"]["enable_gobuster"] or cfg["fuzzing"]["enable_dirb"] or cfg["fuzzing"]["enable_ffuf"]:
                logger.log(f"Phase 8: Directory fuzzing for {target}", "INFO")
                target_url = target if target.startswith("http") else f"http://{target}"
                
                # Get appropriate wordlist
                wordlist_path = MERGED_DIR / "all_merged_wordlist.txt"
                if not wordlist_path.exists():
                    # Fallback to smaller wordlist
                    small_wordlist = "\n".join([
                        "admin", "login", "test", "backup", "config", "database", "db",
                        "panel", "api", "v1", "v2", "upload", "uploads", "files", "images",
                        "scripts", "css", "js", "assets", "static", "public", "private"
                    ])
                    atomic_write(wordlist_path, small_wordlist)
                
                if cfg["fuzzing"]["enable_gobuster"]:
                    gobuster_out = tdir / "gobuster_dirs.txt"
                    run_gobuster(target_url, wordlist_path, gobuster_out, cfg["fuzzing"]["extensions"], env)
                    if gobuster_out.exists():
                        dirs = []
                        for line in gobuster_out.read_text(encoding="utf-8", errors="ignore").splitlines():
                            if line.strip() and not line.startswith("="):
                                dirs.append(line.strip())
                        results["directories"].extend(dirs)
                
                if cfg["fuzzing"]["enable_ffuf"]:
                    ffuf_out = tdir / "ffuf_dirs.json"
                    run_ffuf(target_url, wordlist_path, ffuf_out, env)
                    if ffuf_out.exists():
                        try:
                            ffuf_data = json.loads(ffuf_out.read_text())
                            if "results" in ffuf_data:
                                for result in ffuf_data["results"]:
                                    results["directories"].append(f"{result.get('url', '')} (Status: {result.get('status', 'N/A')})")
                        except Exception:
                            pass

            # Phase 9: Endpoint Discovery
            if cfg["endpoints"]["use_waybackurls"] or cfg["endpoints"]["use_gospider"]:
                logger.log(f"Phase 9: Endpoint discovery for {target}", "INFO")
                
                if cfg["endpoints"]["use_waybackurls"]:
                    wayback_out = tdir / "waybackurls.txt"
                    run_waybackurls(host, wayback_out, env)
                    if wayback_out.exists():
                        endpoints = read_lines(wayback_out)
                        results["endpoints"].extend(endpoints[:cfg["endpoints"]["max_urls_per_target"]])
                
                if cfg["endpoints"]["use_gospider"]:
                    gospider_out = tdir / "gospider"
                    run_gospider(target_url, gospider_out, cfg["endpoints"].get("gospider_depth", 3), env)

            # Phase 10: Subdomain Takeover Check
            if cfg["advanced_scanning"]["subdomain_takeover"] and subs:
                logger.log(f"Phase 10: Subdomain takeover check for {target}", "INFO")
                subjack_out = tdir / "subjack_results.txt"
                run_subjack(merged_subs, subjack_out, env)

            results["status"] = "completed"
            logger.log(f"Recon completed for {target}", "SUCCESS")
            # Phase 7: Subdomain Takeover Detection
            if cfg.get("subdomain_takeover", {}).get("enabled", True) and results["subdomains"]:
                logger.log(f"Phase 7: Subdomain takeover detection for {host}", "INFO")
                
                # Create subdomain file for takeover tools
                subs_file = tdir / "subdomains.txt"
                
                # Run subjack
                if cfg.get("subdomain_takeover", {}).get("subjack", True) and which("subjack"):
                    subjack_out = tdir / "subjack_results.txt"
                    run_cmd([
                        "subjack", "-w", str(subs_file), "-t", "100", "-timeout", "30", 
                        "-o", str(subjack_out), "-ssl"
                    ], env=env, timeout=600, check_return=False)
                
                # Run subzy  
                if cfg.get("subdomain_takeover", {}).get("subzy", True):
                    subzy_out = tdir / "subzy_results.json"
                    run_subzy(subs_file, subzy_out, env, cfg)
            
        except Exception as e:
            logger.log(f"Recon error {target}: {e}", "ERROR")
            results["status"] = "failed"
        
        return results

    with ThreadPoolExecutor(max_workers=cfg["limits"]["max_concurrent_scans"]) as ex:
        futs = {ex.submit(per_target, t): t for t in targets}
        for fut in as_completed(futs):
            res = fut.result()
            logger.log(f"Recon complete: {res.get('target')} -> {res.get('status')}", "INFO")

    logger.log("Enhanced recon stage complete", "SUCCESS")

def stage_vuln_scan(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    logger.log("Enhanced vulnerability scan stage started", "INFO")
    vuln_dir = run_dir / "vuln_scan"
    vuln_dir.mkdir(exist_ok=True)
    targets = read_lines(TARGETS)
    if not targets:
        logger.log("No targets, skipping vuln scan", "WARNING")
        return

    def per_target(target: str):
        tdir = vuln_dir / target.replace(".", "_").replace("/", "_")
        tdir.mkdir(exist_ok=True)
        logger.log(f"Starting vulnerability scan for {target}", "INFO")
        
        try:
            # Phase 1: Nuclei Vulnerability Scanning
            logger.log(f"Phase 1: Nuclei scanning for {target}", "INFO")
            nuclei_out = tdir / "nuclei_results.jsonl"
            target_url = target if target.startswith("http") else f"http://{target}"
            run_nuclei_single_target(target_url, nuclei_out, cfg, env)
            
            # Phase 2: Web Application Security Testing
            if cfg.get("advanced_scanning", {}).get("security_headers", True):
                logger.log(f"Phase 2: Security headers analysis for {target}", "INFO")
                headers_out = tdir / "security_headers.json"
                check_security_headers(target_url, headers_out, env)
            
            # Phase 3: CORS Analysis
            if cfg.get("advanced_scanning", {}).get("cors_analysis", True):
                logger.log(f"Phase 3: CORS analysis for {target}", "INFO")
                cors_out = tdir / "cors_analysis.json"
                check_cors_configuration(target_url, cors_out, env)
            
            # Phase 4: Nikto Web Vulnerability Scanner
            logger.log(f"Phase 4: Nikto scanning for {target}", "INFO")
            nikto_out = tdir / "nikto_results.json"
            run_nikto(target_url, nikto_out, env)
            
            # Phase 6: Enhanced API Security Testing
            if cfg.get("advanced_scanning", {}).get("api_discovery", True):
                logger.log(f"Phase 6: API discovery and testing for {target}", "INFO")
                api_out = tdir / "api_discovery.json"
                run_api_discovery(target_url, api_out, env)
            
            # Phase 7: GraphQL Security Testing
            if cfg.get("advanced_scanning", {}).get("graphql_testing", True):
                logger.log(f"Phase 7: GraphQL security testing for {target}", "INFO")
                graphql_out = tdir / "graphql_security.json"
                run_graphql_testing(target_url, graphql_out, env)
            
            # Phase 8: JWT Analysis
            if cfg.get("advanced_scanning", {}).get("jwt_analysis", True):
                logger.log(f"Phase 8: JWT token analysis for {target}", "INFO")
                jwt_out = tdir / "jwt_analysis.json"
                run_jwt_analysis(target_url, jwt_out, env)
            
            # Phase 9: Cloud Storage Bucket Discovery
            if cfg.get("advanced_scanning", {}).get("cloud_storage_buckets", True):
                logger.log(f"Phase 9: Cloud storage discovery for {target}", "INFO")
                cloud_out = tdir / "cloud_storage.json"
                run_cloud_storage_scanning(target_url, cloud_out, env)
            
            # Phase 10: Threat Intelligence Lookup
            if cfg.get("advanced_scanning", {}).get("threat_intelligence", True):
                logger.log(f"Phase 10: Threat intelligence lookup for {target}", "INFO")
                threat_out = tdir / "threat_intelligence.json"
                run_threat_intelligence_lookup(target_url, threat_out, cfg, env)
            
            # Phase 11: Compliance Checks
            if cfg.get("advanced_scanning", {}).get("compliance_checks", True):
                logger.log(f"Phase 11: Compliance security checks for {target}", "INFO")
                compliance_out = tdir / "compliance_checks.json"
                run_compliance_checks(target_url, compliance_out, cfg, env)
            
            # Phase 12: SQL Injection Testing (if enabled)
            if cfg.get("sqlmap_testing", {}).get("enabled", True):
                logger.log(f"Phase 12: SQL injection testing for {target}", "INFO")
                sqlmap_out = tdir / "sqlmap_results"
                run_sqlmap(target_url, sqlmap_out, env, cfg)
                
                # Additional SQL testing
                additional_sql_out = tdir / "additional_sql_results.json"
                run_additional_sql_tests(target_url, additional_sql_out, env, cfg)
            
            # Phase 13: XSS Testing with multiple tools
            if cfg.get("xss_testing", {}).get("enabled", True):
                logger.log(f"Phase 13: XSS testing for {target}", "INFO")
                
                # XSStrike
                xss_out = tdir / "xss_results.json"
                run_xss_strike(target_url, xss_out, env, cfg)
                
                # Dalfox (additional XSS tool)
                dalfox_out = tdir / "dalfox_results.json"
                run_dalfox(target_url, dalfox_out, env, cfg)
            
            # Phase 14: Enhanced Nmap Vulnerability Scanning
            if cfg.get("nmap_scanning", {}).get("enabled", True):
                logger.log(f"Phase 14: Enhanced Nmap scanning for {target}", "INFO")
                nmap_out = tdir / "nmap_results"
                run_enhanced_nmap(target_url, nmap_out, env, cfg)
            
            # Phase 15: Directory and File Fuzzing with Multiple Tools
            if cfg.get("fuzzing", {}).get("enable_ffuf", True):
                logger.log(f"Phase 15a: FFUF directory fuzzing for {target}", "INFO")
                wordlist = get_best_wordlist("directories")
                if wordlist:
                    ffuf_out = tdir / "ffuf_results.json"
                    run_ffuf(target_url, wordlist, ffuf_out, env)
            
            if cfg.get("fuzzing", {}).get("enable_feroxbuster", True):
                logger.log(f"Phase 15b: Feroxbuster directory fuzzing for {target}", "INFO")
                wordlist = get_best_wordlist("directories")
                if wordlist:
                    ferox_out = tdir / "feroxbuster_results.json"
                    run_feroxbuster(target_url, wordlist, ferox_out, env, cfg)
                logger.log(f"Phase 12: SQL injection testing for {target}", "INFO")
                sqlmap_out = tdir / "sqlmap_results"
                sqlmap_out.mkdir(exist_ok=True)
                run_sqlmap(target_url, sqlmap_out, env)
            
            # Phase 13: Additional vulnerability checks from recon data
            logger.log(f"Phase 13: Additional vulnerability checks for {target}", "INFO")
            additional_out = tdir / "additional_vulns.json"
            perform_additional_checks(target, tdir, additional_out, cfg, env)
            
            logger.log(f"Vulnerability scanning completed for {target}", "SUCCESS")
            
        except Exception as e:
            logger.log(f"Vulnerability scan error {target}: {e}", "ERROR")

    with ThreadPoolExecutor(max_workers=cfg["limits"]["max_concurrent_scans"]) as ex:
        futs = [ex.submit(per_target, t) for t in targets]
        for _ in as_completed(futs):
            pass

    # Apply ML-based analysis to all scan results
    if cfg.get("ml_analysis", {}).get("enabled", True):
        logger.log("Applying ML-based vulnerability analysis", "INFO")
        ml_out = vuln_dir / "ml_analysis_results.json"
        run_ml_vulnerability_analysis(vuln_dir, ml_out, cfg)

    logger.log("Enhanced vulnerability scan stage complete", "SUCCESS")

def check_security_headers(target: str, out_file: Path, env: Dict[str, str]):
    """Check for important security headers"""
    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP", 
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "X-XSS-Protection": "XSS Protection",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Permissions Policy"
    }
    
    results = {
        "target": target,
        "headers_present": {},
        "headers_missing": [],
        "security_score": 0
    }
    
    try:
        if which("curl"):
            result = run_cmd(["curl", "-I", "-s", "-k", target], capture=True, timeout=30, check_return=False)
            if result.stdout:
                headers = {}
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                
                for header, description in security_headers.items():
                    if header in headers:
                        results["headers_present"][header] = {
                            "value": headers[header],
                            "description": description
                        }
                        results["security_score"] += 1
                    else:
                        results["headers_missing"].append({
                            "header": header,
                            "description": description
                        })
                
                results["security_score"] = (results["security_score"] / len(security_headers)) * 100
                
        atomic_write(out_file, json.dumps(results, indent=2))
    except Exception as e:
        logger.log(f"Security headers check error: {e}", "WARNING")

def check_cors_configuration(target: str, out_file: Path, env: Dict[str, str]):
    """Check CORS configuration for potential issues"""
    cors_results = {
        "target": target,
        "cors_enabled": False,
        "wildcard_origin": False,
        "credentials_allowed": False,
        "unsafe_headers": [],
        "risk_level": "low"
    }
    
    try:
        if which("curl"):
            # Test with a malicious origin
            result = run_cmd([
                "curl", "-I", "-s", "-k", "-H", "Origin: https://malicious.com", target
            ], capture=True, timeout=30, check_return=False)
            
            if result.stdout:
                headers = {}
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                
                if "access-control-allow-origin" in headers:
                    cors_results["cors_enabled"] = True
                    origin_value = headers["access-control-allow-origin"]
                    
                    if origin_value == "*":
                        cors_results["wildcard_origin"] = True
                        cors_results["risk_level"] = "high"
                    elif "malicious.com" in origin_value:
                        cors_results["wildcard_origin"] = True
                        cors_results["risk_level"] = "critical"
                
                if "access-control-allow-credentials" in headers:
                    if headers["access-control-allow-credentials"].lower() == "true":
                        cors_results["credentials_allowed"] = True
                        if cors_results["wildcard_origin"]:
                            cors_results["risk_level"] = "critical"
                
                dangerous_headers = ["access-control-allow-headers", "access-control-allow-methods"]
                for header in dangerous_headers:
                    if header in headers and "*" in headers[header]:
                        cors_results["unsafe_headers"].append(header)
                        cors_results["risk_level"] = "high"
        
        atomic_write(out_file, json.dumps(cors_results, indent=2))
    except Exception as e:
        logger.log(f"CORS analysis error: {e}", "WARNING")

def _check_admin_panels(target: str) -> List[str]:
    """Check for exposed admin panels"""
    admin_paths = [
        "/admin", "/administrator", "/admin.php", "/admin/login.php",
        "/wp-admin", "/administrator/", "/admin/index.php", "/admin/admin.php",
        "/login", "/login.php", "/signin", "/signin.php"
    ]
    
    found_panels = []
    if not which("curl"):
        return found_panels
    
    for path in admin_paths:
        full_url = target.rstrip('/') + path
        response = safe_http_request(full_url, timeout=10)
        if response and ("200 OK" in response or "302 Found" in response):
            found_panels.append(path)
    
    return found_panels

def _check_backup_files(target: str) -> List[str]:
    """Check for exposed backup files"""
    backup_extensions = [".bak", ".backup", ".old", ".orig", ".save", ".tmp"]
    common_files = ["index", "config", "database", "db", "admin", "login"]
    
    found_backups = []
    if not which("curl"):
        return found_backups
    
    for file in common_files:
        for ext in backup_extensions:
            backup_url = f"{target.rstrip('/')}/{file}{ext}"
            response = safe_http_request(backup_url, timeout=5)
            if response and "200 OK" in response:
                found_backups.append(f"{file}{ext}")
    
    return found_backups

def _check_robots_txt(target: str) -> List[str]:
    """Analyze robots.txt for sensitive information"""
    disallowed = []
    if not which("curl"):
        return disallowed
    
    robots_url = f"{target.rstrip('/')}/robots.txt"
    response = safe_http_request(robots_url, timeout=10)
    
    if response and "disallow" in response.lower():
        for line in response.split('\n'):
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    disallowed.append(path)
    
    return disallowed[:10]  # Limit to first 10

def perform_additional_checks(target: str, target_dir: Path, out_file: Path, cfg: Dict[str, Any], env: Dict[str, str]):
    """Perform additional vulnerability checks based on discovered services"""
    additional_vulns = {
        "target": target,
        "checks_performed": [],
        "vulnerabilities": [],
        "recommendations": []
    }
    
    def _perform_checks():
        # Check for common admin panels
        additional_vulns["checks_performed"].append("Admin panel discovery")
        found_panels = _check_admin_panels(target)
        if found_panels:
            additional_vulns["vulnerabilities"].append({
                "type": "Exposed Admin Panels",
                "severity": "medium",
                "description": f"Found {len(found_panels)} potential admin panels",
                "details": found_panels
            })
        
        # Check for common backup files
        additional_vulns["checks_performed"].append("Backup file discovery")
        found_backups = _check_backup_files(target)
        if found_backups:
            additional_vulns["vulnerabilities"].append({
                "type": "Exposed Backup Files", 
                "severity": "high",
                "description": f"Found {len(found_backups)} potential backup files",
                "details": found_backups
            })
        
        # Check robots.txt for sensitive information
        additional_vulns["checks_performed"].append("Robots.txt analysis")
        disallowed_paths = _check_robots_txt(target)
        if disallowed_paths:
            additional_vulns["vulnerabilities"].append({
                "type": "Robots.txt Information Disclosure",
                "severity": "low", 
                "description": "Robots.txt reveals potentially sensitive paths",
                "details": disallowed_paths
            })
        
        # Generate recommendations
        if additional_vulns["vulnerabilities"]:
            additional_vulns["recommendations"].extend([
                "Review and secure exposed admin panels",
                "Remove or protect backup files",
                "Implement proper access controls", 
                "Regular security assessments"
            ])
        
        return atomic_write(out_file, json.dumps(additional_vulns, indent=2))
    
    safe_execute(
        _perform_checks,
        default=False,
        error_msg="Additional checks failed"
    )

def stage_report(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    logger.log("Enhanced reporting stage started", "INFO")
    report_dir = run_dir / "report"
    report_dir.mkdir(exist_ok=True)

    recon_results: Dict[str, Any] = {}
    vuln_results: Dict[str, Any] = {}

    # Load reconnaissance results
    recon_dir = run_dir / "recon"
    if recon_dir.exists():
        for td in recon_dir.iterdir():
            if not td.is_dir():
                continue
            tname = td.name
            
            # Enhanced recon data collection
            target_data = {
                "subdomains": read_lines(td / "subdomains.txt"),
                "open_ports": [],
                "http_info": [],
                "technology_stack": {},
                "ssl_info": {},
                "network_info": {},
                "directories": [],
                "dns_info": {}
            }
            
            # Parse port information
            op = td / "open_ports.txt"
            if op.exists():
                for line in op.read_text(encoding="utf-8", errors="ignore").splitlines():
                    l = line.strip()
                    if l and ":" in l:
                        try:
                            h, port = l.rsplit(":", 1)
                            target_data["open_ports"].append({"host": h, "port": int(port), "proto": "tcp"})
                        except Exception:
                            pass
            
            # Parse HTTP information
            httpx = td / "httpx_output.jsonl"
            if httpx.exists():
                for line in httpx.read_text(encoding="utf-8", errors="ignore").splitlines():
                    try:
                        target_data["http_info"].append(json.loads(line))
                    except Exception:
                        pass
            
            # Load additional data files
            additional_files = {
                "dns_info.json": "dns_info",
                "whatweb.json": "technology_stack", 
                "ssl_analysis.json": "ssl_info"
            }
            
            for filename, key in additional_files.items():
                file_path = td / filename
                if file_path.exists():
                    try:
                        target_data[key] = json.loads(file_path.read_text())
                    except Exception:
                        pass
            
            # Load network analysis
            network_dir = td / "network_analysis"
            if network_dir.exists():
                network_info = {}
                for file in network_dir.glob("*.txt"):
                    try:
                        network_info[file.stem] = file.read_text()
                    except Exception:
                        pass
                target_data["network_info"] = network_info
            
            recon_results[tname] = target_data

    # Load vulnerability scan results
    vuln_dir = run_dir / "vuln_scan"
    if vuln_dir.exists():
        for td in vuln_dir.iterdir():
            if not td.is_dir():
                continue
            tname = td.name
            
            vuln_data = {
                "nuclei_raw": [],
                "nuclei_parsed": [],
                "security_headers": {},
                "cors_analysis": {},
                "nikto_results": {},
                "additional_vulns": {},
                "risk_score": 0
            }
            
            # Parse Nuclei results
            nuc = td / "nuclei_results.jsonl"
            if nuc.exists():
                nuclei_lines = nuc.read_text(encoding="utf-8", errors="ignore").splitlines()
                vuln_data["nuclei_raw"] = nuclei_lines
                
                # Parse and categorize nuclei findings
                parsed_nuclei = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
                for line in nuclei_lines:
                    try:
                        finding = json.loads(line)
                        severity = finding.get("info", {}).get("severity", "unknown").lower()
                        if severity in parsed_nuclei:
                            parsed_nuclei[severity].append(finding)
                        vuln_data["risk_score"] += {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}.get(severity, 0)
                    except Exception:
                        pass
                vuln_data["nuclei_parsed"] = parsed_nuclei
            
            # Load additional vulnerability data
            additional_vuln_files = {
                "security_headers.json": "security_headers",
                "cors_analysis.json": "cors_analysis", 
                "nikto_results.json": "nikto_results",
                "additional_vulns.json": "additional_vulns"
            }
            
            for filename, key in additional_vuln_files.items():
                file_path = td / filename
                if file_path.exists():
                    try:
                        vuln_data[key] = json.loads(file_path.read_text())
                    except Exception:
                        pass
            
            vuln_results[tname] = vuln_data

    # Calculate overall risk assessment
    overall_risk = calculate_risk_score(vuln_results)
    
    report_data = {
        "run_id": run_dir.name,
        "timestamp": datetime.now().isoformat(),
        "targets": read_lines(TARGETS),
        "recon_results": recon_results,
        "vuln_scan_results": vuln_results,
        "configuration": cfg,
        "risk_assessment": overall_risk,
        "executive_summary": generate_executive_summary(recon_results, vuln_results, overall_risk)
    }

    # Generate reports in multiple formats
    formats = cfg.get("report", {}).get("formats", ["html", "json"])
    
    if "json" in formats:
        atomic_write(report_dir / "report.json", json.dumps(report_data, indent=2))
        logger.log("JSON report generated", "SUCCESS")
    
    if "csv" in formats:
        generate_csv_report(report_data, report_dir)
        logger.log("CSV report generated", "SUCCESS")
    
    if "sarif" in formats:
        generate_sarif_report(report_data, report_dir)
        logger.log("SARIF report generated", "SUCCESS")
    
    if "html" in formats:
        generate_enhanced_html_report(report_data, report_dir)
        logger.log("Enhanced HTML report generated", "SUCCESS")

    logger.log(f"Enhanced report written: {report_dir}", "SUCCESS")

def calculate_risk_score(vuln_results: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate overall risk assessment"""
    total_score = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    # Safety check: ensure vuln_results is a dictionary
    if not isinstance(vuln_results, dict):
        logger.log(f"Warning: vuln_results is not a dictionary, got {type(vuln_results)}", "WARNING")
        vuln_results = {}
    
    for target, data in vuln_results.items():
        # Safety check: ensure data is a dictionary
        if not isinstance(data, dict):
            logger.log(f"Warning: data for target {target} is not a dictionary, skipping", "WARNING")
            continue
            
        total_score += data.get("risk_score", 0)
        nuclei_parsed = data.get("nuclei_parsed", {})
        
        # Safety check: ensure nuclei_parsed is a dictionary
        if not isinstance(nuclei_parsed, dict):
            logger.log(f"Warning: nuclei_parsed for target {target} is not a dictionary, skipping", "DEBUG")
            continue
            
        for severity, findings in nuclei_parsed.items():
            if severity in severity_counts and isinstance(findings, (list, tuple)):
                severity_counts[severity] += len(findings)
    
    # Calculate risk level
    if severity_counts["critical"] > 0 or total_score > 50:
        risk_level = "CRITICAL"
    elif severity_counts["high"] > 2 or total_score > 30:
        risk_level = "HIGH"
    elif severity_counts["medium"] > 5 or total_score > 15:
        risk_level = "MEDIUM"
    elif severity_counts["low"] > 10 or total_score > 5:
        risk_level = "LOW"
    else:
        risk_level = "INFORMATIONAL"
    
    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "severity_breakdown": severity_counts,
        "recommendations": generate_risk_recommendations(risk_level, severity_counts)
    }

def generate_risk_recommendations(risk_level: str, severity_counts: Dict[str, int]) -> List[str]:
    """Generate recommendations based on risk level"""
    recommendations = []
    
    if severity_counts["critical"] > 0:
        recommendations.append("[CRITICAL] IMMEDIATE ACTION REQUIRED: Critical vulnerabilities found")
        recommendations.append("• Patch critical vulnerabilities immediately")
        recommendations.append("• Consider taking affected systems offline until patched")
    
    if severity_counts["high"] > 0:
        recommendations.append("🔴 HIGH PRIORITY: Address high-severity vulnerabilities within 24-48 hours")
        recommendations.append("• Review and patch high-severity findings")
        recommendations.append("• Implement additional monitoring")
    
    if severity_counts["medium"] > 0:
        recommendations.append("🟡 MEDIUM PRIORITY: Address medium-severity vulnerabilities within 1-2 weeks")
        recommendations.append("• Plan patching for medium-severity issues")
        recommendations.append("• Review configuration hardening")
    
    recommendations.extend([
        "• Regular security assessments",
        "• Implement security headers",
        "• Review access controls",
        "• Security awareness training"
    ])
    
    return recommendations

def generate_executive_summary(recon_results: Dict[str, Any], vuln_results: Dict[str, Any], risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Generate executive summary"""
    total_subdomains = sum(len(data.get("subdomains", [])) for data in recon_results.values())
    total_ports = sum(len(data.get("open_ports", [])) for data in recon_results.values())
    total_services = sum(len(data.get("http_info", [])) for data in recon_results.values())
    
    return {
        "targets_scanned": len(recon_results),
        "subdomains_discovered": total_subdomains,
        "open_ports_found": total_ports,
        "http_services_identified": total_services,
        "vulnerabilities_found": risk_assessment["severity_breakdown"],
        "overall_risk": risk_assessment["risk_level"],
        "key_findings": extract_key_findings(vuln_results),
        "scan_completion": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def extract_key_findings(vuln_results: Dict[str, Any]) -> List[str]:
    """Extract key findings for executive summary"""
    findings = []
    
    for target, data in vuln_results.items():
        nuclei_parsed = data.get("nuclei_parsed", {})
        
        # Critical findings
        if nuclei_parsed.get("critical"):
            findings.append(f"[ALERT] {target}: {len(nuclei_parsed['critical'])} critical vulnerabilities")
        
        # Security headers issues
        headers = data.get("security_headers", {})
        if headers.get("security_score", 100) < 50:
            findings.append(f"🔒 {target}: Poor security headers configuration")
        
        # CORS issues
        cors = data.get("cors_analysis", {})
        if cors.get("risk_level") in ["high", "critical"]:
            findings.append(f"🌐 {target}: Dangerous CORS configuration")
    
    return findings[:10]  # Limit to top 10 findings

def generate_csv_report(report_data: Dict[str, Any], report_dir: Path):
    """Generate CSV format report"""
    import csv
    
    # Vulnerabilities CSV
    vuln_csv = report_dir / "vulnerabilities.csv"
    with open(vuln_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Target', 'Vulnerability', 'Severity', 'Description', 'Template'])
        
        for target, data in report_data["vuln_scan_results"].items():
            nuclei_parsed = data.get("nuclei_parsed", {})
            for severity, findings in nuclei_parsed.items():
                for finding in findings:
                    info = finding.get("info", {})
                    writer.writerow([
                        target,
                        info.get("name", "Unknown"),
                        severity.upper(),
                        info.get("description", ""),
                        finding.get("template-id", "")
                    ])

def generate_sarif_report(report_data: Dict[str, Any], report_dir: Path):
    """Generate SARIF format report for integration with security tools"""
    sarif_data = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Bl4ckC3ll_PANTHEON",
                    "version": "9.0.0-enhanced",
                    "informationUri": "https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON"
                }
            },
            "results": []
        }]
    }
    
    for target, data in report_data["vuln_scan_results"].items():
        nuclei_parsed = data.get("nuclei_parsed", {})
        for severity, findings in nuclei_parsed.items():
            for finding in findings:
                info = finding.get("info", {})
                result = {
                    "ruleId": finding.get("template-id", "unknown"),
                    "message": {"text": info.get("description", "No description")},
                    "level": map_severity_to_sarif(severity),
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("matched-at", target)}
                        }
                    }]
                }
                sarif_data["runs"][0]["results"].append(result)
    
    atomic_write(report_dir / "report.sarif", json.dumps(sarif_data, indent=2))

def map_severity_to_sarif(severity: str) -> str:
    """Map our severity levels to SARIF levels"""
    mapping = {
        "critical": "error",
        "high": "error", 
        "medium": "warning",
        "low": "note",
        "info": "note"
    }
    return mapping.get(severity, "note")

def generate_enhanced_html_report(report_data: Dict[str, Any], report_dir: Path):
    """Generate enhanced HTML report with improved styling"""
    # HTML template with red/yellow color scheme
    def esc(s: str) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def html_recon() -> str:
        chunks: List[str] = []
        for target, data in report_data["recon_results"].items():
            subs = "".join(f"<li>{esc(x)}</li>" for x in data["subdomains"]) or "<li>None</li>"
            ports = "".join(f"<li><span class='port'>{esc(p['host'])}:{p['port']}/{p['proto']}</span></li>" for p in data["open_ports"]) or "<li>None</li>"
            
            # Technology stack
            tech_info = ""
            if data.get("technology_stack"):
                tech_info = f"<h5>[TECH] Technology Stack</h5><pre>{esc(json.dumps(data['technology_stack'], indent=2)[:500])}</pre>"
            
            # Network info
            network_info = ""
            if data.get("network_info"):
                network_info = "<h5>🌐 Network Information</h5>"
                for key, value in data["network_info"].items():
                    network_info += f"<h6>{esc(key.title())}</h6><pre>{esc(str(value)[:300])}</pre>"
            
            chunks.append(f"""
            <div class="target-section">
              <h3>[TARGET] Target: {esc(target)}</h3>
              <div class="info-grid">
                <div class="info-box">
                  <h4>[RECON] Subdomains ({len(data['subdomains'])})</h4>
                  <ul class="subdomain-list">{subs}</ul>
                </div>
                <div class="info-box">
                  <h4>[PORTS] Open Ports ({len(data['open_ports'])})</h4>
                  <ul class="port-list">{ports}</ul>
                </div>
              </div>
              {tech_info}
              {network_info}
            </div>""")
        return "\n".join(chunks)

    def html_vuln() -> str:
        chunks: List[str] = []
        for target, data in report_data["vuln_scan_results"].items():
            nuclei_parsed = data.get("nuclei_parsed", {})
            risk_score = data.get("risk_score", 0)
            
            # Vulnerability summary
            vuln_summary = ""
            total_vulns = sum(len(findings) for findings in nuclei_parsed.values())
            if total_vulns > 0:
                vuln_summary = f"""
                <div class="vuln-summary">
                  <h4>[REPORT] Vulnerability Summary</h4>
                  <div class="severity-grid">
                    <span class="severity critical">Critical: {len(nuclei_parsed.get('critical', []))}</span>
                    <span class="severity high">High: {len(nuclei_parsed.get('high', []))}</span>
                    <span class="severity medium">Medium: {len(nuclei_parsed.get('medium', []))}</span>
                    <span class="severity low">Low: {len(nuclei_parsed.get('low', []))}</span>
                  </div>
                  <div class="risk-score">Risk Score: <span class="score">{risk_score}</span></div>
                </div>"""
            
            # Detailed findings
            findings_html = ""
            for severity in ["critical", "high", "medium", "low"]:
                findings = nuclei_parsed.get(severity, [])
                if findings:
                    findings_html += f"<h5 class='severity-header {severity}'>[ALERT] {severity.title()} ({len(findings)})</h5>"
                    findings_html += "<ul class='findings-list'>"
                    for finding in findings[:10]:  # Limit to first 10 per severity
                        info = finding.get("info", {})
                        findings_html += f"<li><strong>{esc(info.get('name', 'Unknown'))}</strong>: {esc(info.get('description', 'No description')[:100])}</li>"
                    if len(findings) > 10:
                        findings_html += f"<li><em>... and {len(findings) - 10} more</em></li>"
                    findings_html += "</ul>"
            
            # Additional security checks
            additional_checks = ""
            if data.get("security_headers"):
                headers = data["security_headers"]
                score = headers.get("security_score", 0)
                additional_checks += f"""
                <h5>🔒 Security Headers (Score: {score:.1f}%)</h5>
                <p>Missing: {len(headers.get('headers_missing', []))} headers</p>"""
            
            if data.get("cors_analysis"):
                cors = data["cors_analysis"]
                risk = cors.get("risk_level", "unknown")
                additional_checks += f"<h5>🌐 CORS Analysis: <span class='risk-{risk}'>{risk.title()}</span></h5>"
            
            chunks.append(f"""
            <div class="target-section">
              <h3>[TARGET] Target: {esc(target)}</h3>
              {vuln_summary}
              {findings_html}
              {additional_checks}
            </div>""")
        return "\n".join(chunks)

    # Executive summary HTML
    exec_summary = report_data.get("executive_summary", {})
    risk_assessment = report_data.get("risk_assessment", {})
    
    summary_html = f"""
    <div class="executive-summary">
      <h2>[SUMMARY] Executive Summary</h2>
      <div class="summary-grid">
        <div class="summary-item">
          <span class="number">{exec_summary.get('targets_scanned', 0)}</span>
          <span class="label">Targets Scanned</span>
        </div>
        <div class="summary-item">
          <span class="number">{exec_summary.get('subdomains_discovered', 0)}</span>
          <span class="label">Subdomains Found</span>
        </div>
        <div class="summary-item">
          <span class="number">{exec_summary.get('open_ports_found', 0)}</span>
          <span class="label">Open Ports</span>
        </div>
        <div class="summary-item risk-{risk_assessment.get('risk_level', 'unknown').lower()}">
          <span class="number">{risk_assessment.get('risk_level', 'UNKNOWN')}</span>
          <span class="label">Risk Level</span>
        </div>
      </div>
      
      <div class="key-findings">
        <h3>[RECON] Key Findings</h3>
        <ul>
          {"".join(f"<li>{esc(finding)}</li>" for finding in exec_summary.get('key_findings', []))}
        </ul>
      </div>
      
      <div class="recommendations">
        <h3>💡 Recommendations</h3>
        <ul>
          {"".join(f"<li>{esc(rec)}</li>" for rec in risk_assessment.get('recommendations', []))}
        </ul>
      </div>
    </div>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>[SECURITY] Penetration Test Report - {esc(report_data['run_id'])}</title>
  <style>
    body {{ 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
      margin: 0; padding: 20px; 
      background: linear-gradient(135deg, #1a1a1a 0%, #2d1810 100%);
      color: #fff; min-height: 100vh;
    }}
    
    .header {{
      text-align: center; padding: 30px 0; 
      background: linear-gradient(90deg, #dc143c, #ff6b35);
      margin: -20px -20px 30px -20px;
      box-shadow: 0 4px 20px rgba(220, 20, 60, 0.3);
    }}
    
    h1 {{ color: #fff; font-size: 2.5em; margin: 0; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }}
    h2 {{ color: #ffcc00; border-bottom: 2px solid #dc143c; padding-bottom: 10px; }}
    h3 {{ color: #ff6b35; }}
    h4 {{ color: #ffcc00; }}
    h5 {{ color: #ffa500; }}
    
    .executive-summary {{
      background: linear-gradient(135deg, #2d1810, #1a1a1a);
      padding: 25px; border-radius: 10px; margin-bottom: 30px;
      border: 1px solid #dc143c; box-shadow: 0 4px 15px rgba(220, 20, 60, 0.2);
    }}
    
    .summary-grid {{ 
      display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
      gap: 20px; margin: 20px 0; 
    }}
    
    .summary-item {{ 
      text-align: center; padding: 20px; 
      background: rgba(220, 20, 60, 0.1); border-radius: 8px;
      border: 1px solid rgba(220, 20, 60, 0.3);
    }}
    
    .summary-item .number {{ 
      display: block; font-size: 2em; font-weight: bold; 
      color: #ffcc00; text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
    }}
    
    .summary-item .label {{ font-size: 0.9em; color: #ccc; }}
    
    .risk-critical {{ border-color: #ff0000 !important; background: rgba(255, 0, 0, 0.1) !important; }}
    .risk-high {{ border-color: #ff6600 !important; background: rgba(255, 102, 0, 0.1) !important; }}
    .risk-medium {{ border-color: #ffaa00 !important; background: rgba(255, 170, 0, 0.1) !important; }}
    .risk-low {{ border-color: #00aa00 !important; background: rgba(0, 170, 0, 0.1) !important; }}
    
    .section {{ 
      margin-bottom: 30px; padding: 20px; 
      background: rgba(45, 24, 16, 0.6); border-radius: 10px;
      border: 1px solid rgba(220, 20, 60, 0.3);
    }}
    
    .target-section {{ 
      background: rgba(45, 24, 16, 0.8); padding: 20px; margin: 15px 0; 
      border-radius: 8px; border-left: 4px solid #dc143c;
    }}
    
    .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 15px 0; }}
    .info-box {{ background: rgba(0,0,0,0.3); padding: 15px; border-radius: 6px; }}
    
    .subdomain-list, .port-list, .findings-list {{ 
      max-height: 200px; overflow-y: auto; 
      background: rgba(0,0,0,0.4); padding: 10px; border-radius: 4px;
    }}
    
    .port {{ color: #ffcc00; font-family: monospace; }}
    
    .vuln-summary {{ 
      background: rgba(220, 20, 60, 0.1); padding: 15px; 
      border-radius: 6px; margin: 15px 0;
    }}
    
    .severity-grid {{ display: flex; gap: 15px; flex-wrap: wrap; margin: 10px 0; }}
    .severity {{ 
      padding: 5px 12px; border-radius: 15px; font-weight: bold; 
      text-transform: uppercase; font-size: 0.8em;
    }}
    .severity.critical {{ background: #ff0000; color: #fff; }}
    .severity.high {{ background: #ff6600; color: #fff; }}
    .severity.medium {{ background: #ffaa00; color: #000; }}
    .severity.low {{ background: #00aa00; color: #fff; }}
    
    .severity-header {{ margin-top: 20px; }}
    .severity-header.critical {{ color: #ff4444; }}
    .severity-header.high {{ color: #ff8844; }}
    .severity-header.medium {{ color: #ffcc44; }}
    .severity-header.low {{ color: #44ff44; }}
    
    .risk-score {{ margin-top: 10px; }}
    .score {{ 
      color: #ffcc00; font-weight: bold; font-size: 1.2em;
      text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
    }}
    
    pre {{ 
      background: rgba(0,0,0,0.6); padding: 15px; border-radius: 6px; 
      overflow-x: auto; border-left: 3px solid #dc143c;
      color: #f0f0f0; font-family: 'Courier New', monospace;
    }}
    
    ul {{ line-height: 1.6; }}
    li {{ margin-bottom: 5px; }}
    
    .key-findings, .recommendations {{ 
      background: rgba(0,0,0,0.3); padding: 15px; 
      border-radius: 6px; margin: 15px 0;
    }}
    
    @media (max-width: 768px) {{
      .info-grid {{ grid-template-columns: 1fr; }}
      .severity-grid {{ flex-direction: column; }}
      .summary-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="header">
    <h1>[SECURITY] Bl4ckC3ll_PANTHEON Security Assessment</h1>
    <p><strong>Run ID:</strong> {esc(report_data['run_id'])}</p>
    <p><strong>Generated:</strong> {esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
  </div>

  {summary_html}

  <div class="section">
    <h2>[TARGET] Target Information</h2>
    <ul>{"".join(f"<li><strong>{esc(t)}</strong></li>" for t in report_data["targets"])}</ul>
  </div>

  <div class="section">
    <h2>[RECON] Reconnaissance Results</h2>
    {html_recon()}
  </div>

  <div class="section">
    <h2>[ALERT] Vulnerability Assessment</h2>
    {html_vuln()}
  </div>

  <div class="section">
    <h2>⚙️ Scan Configuration</h2>
    <pre>{esc(json.dumps(report_data.get('configuration', {}), indent=2))}</pre>
  </div>
</body>
</html>
"""
    atomic_write(report_dir / "report.html", html)
    logger.log("Enhanced HTML report with red/yellow theme generated", "SUCCESS")

# ---------- Plugin Management ----------
def load_plugins() -> Dict[str, Any]:
    plugins: Dict[str, Any] = {}
    PLUGINS_DIR.mkdir(exist_ok=True)
    for plugin_file in PLUGINS_DIR.glob("*.py"):
        if plugin_file.name == "__init__.py":
            continue
        try:
            spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)  # type: ignore
                if hasattr(module, "plugin_info") and hasattr(module, "execute"):
                    plugins[plugin_file.stem] = {"info": module.plugin_info, "execute": module.execute, "enabled": True}
                    logger.log(f"Loaded plugin: {plugin_file.stem}", "INFO")
                else:
                    logger.log(f"Plugin missing required symbols: {plugin_file.stem}", "WARNING")
        except Exception as e:
            logger.log(f"Plugin load failed {plugin_file.stem}: {e}", "ERROR")
    return plugins

def create_plugin_template(plugin_name: str):
    template = f"""# Plugin: {plugin_name}
# Provide 'plugin_info' and 'execute(run_dir: Path, env: Dict[str,str], cfg: Dict[str,Any])'
from pathlib import Path
from typing import Dict, Any

plugin_info = {{
    "name": "{plugin_name}",
    "description": "Example plugin that writes a file.",
    "version": "1.0.0",
    "author": "{AUTHOR}"
}}

def execute(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    out = run_dir / "plugin_{plugin_name}.txt"
    out.write_text("Hello from plugin {plugin_name}\\n")
    print(f"[PLUGIN] Wrote: {{out}}")
"""
    atomic_write(PLUGINS_DIR / f"{plugin_name}.py", template)
    logger.log(f"Plugin template created: {PLUGINS_DIR / (plugin_name + '.py')}", "SUCCESS")

def execute_plugin(plugin_name: str, run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    plugins = load_plugins()
    if plugin_name in plugins and plugins[plugin_name].get("enabled", False):
        try:
            plugins[plugin_name]["execute"](run_dir, env, cfg)
            logger.log(f"Plugin executed: {plugin_name}", "SUCCESS")
        except Exception as e:
            logger.log(f"Plugin error {plugin_name}: {e}", "ERROR")
    else:
        logger.log(f"Plugin not found/enabled: {plugin_name}", "WARNING")

# ---------- Menu ----------
BANNER = r"""
██████╗ ██╗      █████╗ ██╗  ██╗ ██████╗██╗  ██╗ ██████╗ ███████╗██╗     ██╗
██╔══██╗██║     ██╔══██╗██║ ██╔╝██╔════╝██║ ██╔╝██╔════╝ ██╔════╝██║     ██║
██████╔╝██║     ███████║█████╔╝ ██║     █████╔╝ ██║  ███╗█████╗  ██║     ██║
██╔══██╗██║     ██╔══██║██╔═██╗ ██║     ██╔═██╗ ██║   ██║██╔══╝  ██║     ██║
██████╔╝███████╗██║  ██║██║  ██╗╚██████╗██║  ██╗╚██████╔╝███████╗███████╗███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝
"""

def display_menu():
    print("\n\033[31m" + "="*80 + "\033[0m")
    print("\033[91m" + "BL4CKC3LL_P4NTH30N - ENHANCED SECURITY TESTING FRAMEWORK".center(80) + "\033[0m")
    print("\033[31m" + "="*80 + "\033[0m")
    print("\033[93m1. [TARGET] Manage Targets\033[0m")
    print("\033[93m2. [REFRESH] Refresh Sources + Merge Wordlists\033[0m")
    print("\033[93m3. [RECON] Enhanced Reconnaissance\033[0m")
    print("\033[93m4. [VULN] Advanced Vulnerability Scan\033[0m")
    print("\033[93m5. [FULL] Full Pipeline (Recon + Vuln + Report)\033[0m")
    print("\033[93m6. [REPORT] Generate Enhanced Report\033[0m")
    print("\033[93m7. [CONFIG] Settings & Configuration\033[0m")
    print("\033[93m8. [PLUGIN] Plugins Management\033[0m")
    print("\033[93m9. [VIEW] View Last Report\033[0m")
    print("\033[93m10. [NET] Network Analysis Tools\033[0m")
    print("\033[93m11. [ASSESS] Security Assessment Summary\033[0m")
    print("\033[92m12. [AI] AI-Powered Vulnerability Analysis\033[0m")
    print("\033[92m13. [CLOUD] Cloud Security Assessment\033[0m")
    print("\033[92m14. [API] API Security Testing\033[0m")
    print("\033[92m15. [COMPLY] Compliance & Risk Assessment\033[0m")
    print("\033[92m16. [CICD] CI/CD Integration Mode\033[0m")
    print("\033[96m17. [ESLINT] ESLint Security Check\033[0m")
    print("\033[96m18. [BUGBOUNTY] Bug Bounty Automation\033[0m")
    print("\033[96m19. [AUTOCHAIN] Automated Testing Chain\033[0m")
    print("\033[92m20. [TUI] Launch Advanced TUI Interface\033[0m")
    print("\033[91m21. [EXIT] Exit\033[0m")
    print("\033[31m" + "="*80 + "\033[0m")

def get_choice() -> int:
    try:
        s = input("\n\033[93mSelect (1-21): \033[0m").strip()
        if s.isdigit():
            n = int(s)
            if 1 <= n <= 21:
                return n
    except (EOFError, KeyboardInterrupt):
        return 21
    except Exception:
        pass
    return 12

def run_full_pipeline():
    """Run the complete pipeline: recon -> vuln scan -> report"""
    cfg = load_cfg()
    env = env_with_lists()
    rd = new_run()
    stop_event, th = create_resource_monitor_thread(cfg)
    
    try:
        logger.log("[START] Starting full security assessment pipeline", "INFO")
        
        # Phase 1: Enhanced Reconnaissance
        logger.log("Phase 1: Enhanced Reconnaissance", "INFO")
        stage_recon(rd, env, cfg)
        
        # Phase 2: Advanced Vulnerability Scanning
        logger.log("Phase 2: Advanced Vulnerability Scanning", "INFO")
        stage_vuln_scan(rd, env, cfg)
        
        # Phase 3: Enhanced Reporting
        logger.log("Phase 3: Enhanced Reporting", "INFO")
        stage_report(rd, env, cfg)
        
        logger.log(f"🎉 Full pipeline complete! Run: {rd}", "SUCCESS")
        
        # Auto-open report if configured
        if cfg.get("report", {}).get("auto_open_html", True):
            html_report = rd / "report" / "report.html"
            if html_report.exists():
                try:
                    webbrowser.open(html_report.as_uri())
                    logger.log("[REPORT] Report opened in browser", "SUCCESS")
                except Exception:
                    logger.log(f"[REPORT] View report at: {html_report}", "INFO")
        
    finally:
        cleanup_resource_monitor(stop_event, th)

def settings_menu():
    """Enhanced settings and configuration menu"""
    while True:
        print("\n\033[31m" + "="*80 + "\033[0m")
        print("\033[91m" + "SETTINGS & CONFIGURATION".center(80) + "\033[0m")
        print("\033[31m" + "="*80 + "\033[0m")
        print("\033[93m1. [TECH] View Current Configuration\033[0m")
        print("\033[93m2. ⚙️ Scan Settings\033[0m")
        print("\033[93m3. [REPORT] Report Settings\033[0m")
        print("\033[93m4. 🌐 Network Settings\033[0m")
        print("\033[93m5. [SECURITY] Security Settings\033[0m")
        print("\033[93m6. 🔄 Reset to Defaults\033[0m")
        print("\033[93m7. 💾 Save Configuration\033[0m")
        print("\033[91m8. ⬅️ Back to Main Menu\033[0m")
        
        try:
            choice = input("\n\033[93mSelect (1-8): \033[0m").strip()
            cfg = load_cfg()
            
            if choice == "1":
                print("\n\033[96m=== Current Configuration ===\033[0m")
                print(json.dumps(cfg, indent=2))
                input("\nPress Enter to continue...")
                
            elif choice == "2":
                configure_scan_settings(cfg)
                
            elif choice == "3":
                configure_report_settings(cfg)
                
            elif choice == "4":
                configure_network_settings(cfg)
                
            elif choice == "5":
                configure_security_settings(cfg)
                
            elif choice == "6":
                if input("\n[WARNING] Reset all settings to defaults? (yes/no): ").lower() == "yes":
                    save_cfg(DEFAULT_CFG)
                    logger.log("Configuration reset to defaults", "SUCCESS")
                    
            elif choice == "7":
                save_cfg(cfg)
                logger.log("Configuration saved", "SUCCESS")
                
            elif choice == "8":
                break
                
        except Exception as e:
            logger.log(f"Settings error: {e}", "ERROR")

def configure_scan_settings(cfg: Dict[str, Any]):
    """Configure scanning-related settings"""
    print("\n\033[96m=== Scan Settings ===\033[0m")
    
    try:
        # Concurrency settings
        current_concurrent = cfg["limits"]["max_concurrent_scans"]
        new_concurrent = input(f"Max concurrent scans ({current_concurrent}): ").strip()
        if new_concurrent.isdigit():
            cfg["limits"]["max_concurrent_scans"] = int(new_concurrent)
        
        # Rate limiting
        current_rps = cfg["limits"]["rps"]
        new_rps = input(f"Requests per second ({current_rps}): ").strip()
        if new_rps.isdigit():
            cfg["limits"]["rps"] = int(new_rps)
        
        # Nuclei settings
        current_severity = cfg["nuclei"]["severity"]
        print(f"Current Nuclei severity filter: {current_severity}")
        print("Available: info,low,medium,high,critical")
        new_severity = input(f"Nuclei severity ({current_severity}): ").strip()
        if new_severity:
            cfg["nuclei"]["severity"] = new_severity
        
        # Advanced scanning options
        for key, description in [
            ("ssl_analysis", "SSL/TLS Analysis"),
            ("dns_enumeration", "DNS Enumeration"),
            ("technology_detection", "Technology Detection"),
            ("subdomain_takeover", "Subdomain Takeover Check"),
            ("cors_analysis", "CORS Analysis"),
            ("security_headers", "Security Headers Check")
        ]:
            current = cfg["advanced_scanning"].get(key, True)
            response = input(f"{description} ({'enabled' if current else 'disabled'}) [y/n]: ").strip().lower()
            if response in ['y', 'yes']:
                cfg["advanced_scanning"][key] = True
            elif response in ['n', 'no']:
                cfg["advanced_scanning"][key] = False
        
        save_cfg(cfg)
        logger.log("Scan settings updated", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Error updating scan settings: {e}", "ERROR")

def configure_report_settings(cfg: Dict[str, Any]):
    """Configure reporting settings"""
    print("\n\033[96m=== Report Settings ===\033[0m")
    
    try:
        # Report formats
        current_formats = cfg["report"]["formats"]
        print(f"Current formats: {', '.join(current_formats)}")
        print("Available: html, json, csv, sarif")
        new_formats = input("Report formats (comma-separated): ").strip()
        if new_formats:
            cfg["report"]["formats"] = [f.strip() for f in new_formats.split(',')]
        
        # Auto-open HTML
        current_auto_open = cfg["report"]["auto_open_html"]
        response = input(f"Auto-open HTML report ({'yes' if current_auto_open else 'no'}) [y/n]: ").strip().lower()
        if response in ['y', 'yes']:
            cfg["report"]["auto_open_html"] = True
        elif response in ['n', 'no']:
            cfg["report"]["auto_open_html"] = False
        
        # Risk scoring
        response = input(f"Enable risk scoring [y/n]: ").strip().lower()
        if response in ['y', 'yes']:
            cfg["report"]["risk_scoring"] = True
        elif response in ['n', 'no']:
            cfg["report"]["risk_scoring"] = False
        
        save_cfg(cfg)
        logger.log("Report settings updated", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Error updating report settings: {e}", "ERROR")

def configure_network_settings(cfg: Dict[str, Any]):
    """Configure network analysis settings"""
    print("\n\033[96m=== Network Settings ===\033[0m")
    
    try:
        for key, description in [
            ("traceroute", "Traceroute Analysis"),
            ("whois_lookup", "WHOIS Lookup"),
            ("reverse_dns", "Reverse DNS Lookup"),
            ("asn_lookup", "ASN Lookup"),
            ("geolocation", "Geolocation Analysis")
        ]:
            current = cfg["network_analysis"].get(key, True)
            response = input(f"{description} ({'enabled' if current else 'disabled'}) [y/n]: ").strip().lower()
            if response in ['y', 'yes']:
                cfg["network_analysis"][key] = True
            elif response in ['n', 'no']:
                cfg["network_analysis"][key] = False
        
        save_cfg(cfg)
        logger.log("Network settings updated", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Error updating network settings: {e}", "ERROR")

def configure_security_settings(cfg: Dict[str, Any]):
    """Configure security-related settings"""
    print("\n\033[96m=== Security Settings ===\033[0m")
    
    try:
        # Fuzzing settings
        for key, description in [
            ("enable_dirb", "Directory Brute Force (dirb)"),
            ("enable_gobuster", "Directory Brute Force (gobuster)"),
            ("enable_ffuf", "Fast Web Fuzzer (ffuf)")
        ]:
            current = cfg["fuzzing"].get(key, True)
            response = input(f"{description} ({'enabled' if current else 'disabled'}) [y/n]: ").strip().lower()
            if response in ['y', 'yes']:
                cfg["fuzzing"][key] = True
            elif response in ['n', 'no']:
                cfg["fuzzing"][key] = False
        
        # Resource management
        print("\n--- Resource Management ---")
        for key, description, default in [
            ("cpu_threshold", "CPU Threshold (%)", 85),
            ("memory_threshold", "Memory Threshold (%)", 90),
            ("disk_threshold", "Disk Threshold (%)", 95)
        ]:
            current = cfg["resource_management"].get(key, default)
            new_value = input(f"{description} ({current}): ").strip()
            if new_value.isdigit():
                cfg["resource_management"][key] = int(new_value)
        
        save_cfg(cfg)
        logger.log("Security settings updated", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Error updating security settings: {e}", "ERROR")

def network_tools_menu():
    """Network analysis tools menu"""
    while True:
        print("\n\033[31m" + "="*80 + "\033[0m")
        print("\033[91m" + "NETWORK ANALYSIS TOOLS".center(80) + "\033[0m")
        print("\033[31m" + "="*80 + "\033[0m")
        print("\033[93m1. 🌐 WHOIS Lookup\033[0m")
        print("\033[93m2. [RECON] DNS Enumeration\033[0m")
        print("\033[93m3. 🛣️ Traceroute Analysis\033[0m")
        print("\033[93m4. 🏢 ASN Lookup\033[0m")
        print("\033[93m5. 🔒 SSL Certificate Analysis\033[0m")
        print("\033[93m6. 📡 Port Scan (Quick)\033[0m")
        print("\033[91m7. ⬅️ Back to Main Menu\033[0m")
        
        try:
            choice = input("\n\033[93mSelect (1-7): \033[0m").strip()
            
            if choice == "1":
                target = input("Enter domain/IP: ").strip()
                if target:
                    perform_whois_lookup(target)
                    
            elif choice == "2":
                domain = input("Enter domain: ").strip()
                if domain:
                    perform_dns_enumeration(domain)
                    
            elif choice == "3":
                target = input("Enter target: ").strip()
                if target:
                    perform_traceroute(target)
                    
            elif choice == "4":
                ip = input("Enter IP address: ").strip()
                if ip:
                    perform_asn_lookup(ip)
                    
            elif choice == "5":
                target = input("Enter HTTPS URL/domain: ").strip()
                if target:
                    perform_ssl_analysis(target)
                    
            elif choice == "6":
                target = input("Enter target: ").strip()
                if target:
                    perform_quick_port_scan(target)
                    
            elif choice == "7":
                break
                
        except Exception as e:
            logger.log(f"Network tools error: {e}", "ERROR")

def perform_whois_lookup(target: str):
    """Perform WHOIS lookup"""
    try:
        if which("whois"):
            result = run_cmd(["whois", target], capture=True, timeout=60, check_return=False)
            if result.stdout:
                print(f"\n\033[96m=== WHOIS Information for {target} ===\033[0m")
                print(result.stdout)
            else:
                logger.log("No WHOIS information found", "WARNING")
        else:
            logger.log("whois command not found", "ERROR")
    except Exception as e:
        logger.log(f"WHOIS lookup error: {e}", "ERROR")
    input("\nPress Enter to continue...")

def perform_dns_enumeration(domain: str):
    """Perform DNS enumeration"""
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    
    print(f"\n\033[96m=== DNS Records for {domain} ===\033[0m")
    
    for record_type in record_types:
        try:
            result = run_cmd(["dig", "+short", record_type, domain], capture=True, timeout=30, check_return=False)
            if result.stdout and result.stdout.strip():
                print(f"\033[93m{record_type} Records:\033[0m")
                for line in result.stdout.strip().split('\n'):
                    print(f"  {line}")
                print()
        except Exception as e:
            logger.log(f"DNS lookup error for {record_type}: {e}", "WARNING")
    
    input("Press Enter to continue...")

def perform_traceroute(target: str):
    """Perform traceroute analysis"""
    try:
        if which("traceroute"):
            print(f"\n\033[96m=== Traceroute to {target} ===\033[0m")
            result = run_cmd(["traceroute", "-m", "15", target], capture=True, timeout=120, check_return=False)
            if result.stdout:
                print(result.stdout)
            else:
                logger.log("No traceroute output", "WARNING")
        else:
            logger.log("traceroute command not found", "ERROR")
    except Exception as e:
        logger.log(f"Traceroute error: {e}", "ERROR")
    input("\nPress Enter to continue...")

def perform_asn_lookup(ip: str):
    """Perform ASN lookup"""
    try:
        # Use WHOIS for ASN information
        if which("whois"):
            result = run_cmd(["whois", "-h", "whois.cymru.com", f" -v {ip}"], capture=True, timeout=30, check_return=False)
            if result.stdout:
                print(f"\n\033[96m=== ASN Information for {ip} ===\033[0m")
                print(result.stdout)
            else:
                logger.log("No ASN information found", "WARNING")
        else:
            logger.log("whois command not found", "ERROR")
    except Exception as e:
        logger.log(f"ASN lookup error: {e}", "ERROR")
    input("\nPress Enter to continue...")

def perform_ssl_analysis(target: str):
    """Perform SSL certificate analysis"""
    try:
        if not target.startswith("https://"):
            target = f"https://{target}"
        
        hostname = target.replace("https://", "").split("/")[0]
        
        print(f"\n\033[96m=== SSL Certificate Analysis for {hostname} ===\033[0m")
        
        result = run_cmd([
            "openssl", "s_client", "-connect", f"{hostname}:443",
            "-servername", hostname, "-showcerts"
        ], capture=True, timeout=30, check_return=False, use_shell=False)
        
        if result.stdout:
            # Extract certificate information
            lines = result.stdout.split('\n')
            cert_info = False
            for line in lines:
                if "Certificate chain" in line:
                    cert_info = True
                if cert_info and ("subject=" in line or "issuer=" in line or "verify" in line):
                    print(line)
        else:
            logger.log("No SSL certificate information found", "WARNING")
            
    except Exception as e:
        logger.log(f"SSL analysis error: {e}", "ERROR")
    input("\nPress Enter to continue...")

def perform_quick_port_scan(target: str):
    """Perform quick port scan"""
    try:
        hostname = target.replace("http://", "").replace("https://", "").split("/")[0]
        
        print(f"\n\033[96m=== Quick Port Scan for {hostname} ===\033[0m")
        
        if which("nmap"):
            result = run_cmd([
                "nmap", "-F", "--open", hostname
            ], capture=True, timeout=120, check_return=False)
            if result.stdout:
                print(result.stdout)
            else:
                logger.log("No open ports found", "WARNING")
        elif which("naabu"):
            result = run_cmd([
                "naabu", "-host", hostname, "-top-ports", "1000"
            ], capture=True, timeout=120, check_return=False)
            if result.stdout:
                print(result.stdout)
            else:
                logger.log("No open ports found", "WARNING")
        else:
            logger.log("No port scanning tools available (nmap or naabu)", "ERROR")
            
    except Exception as e:
        logger.log(f"Port scan error: {e}", "ERROR")
    input("\nPress Enter to continue...")

def security_assessment_summary():
    """Display security assessment summary from latest run"""
    try:
        runs = sorted([d for d in RUNS_DIR.iterdir() if d.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
        if not runs:
            logger.log("No assessment runs found", "WARNING")
            return
        
        latest_run = runs[0]
        report_file = latest_run / "report" / "report.json"
        
        if not report_file.exists():
            logger.log("No report found for latest run", "WARNING")
            return
        
        report_data = json.loads(report_file.read_text())
        
        print(f"\n\033[31m" + "="*80 + "\033[0m")
        print("\033[91m" + "SECURITY ASSESSMENT SUMMARY".center(80) + "\033[0m")
        print(f"\033[31m" + "="*80 + "\033[0m")
        
        # Basic stats
        exec_summary = report_data.get("executive_summary", {})
        risk_assessment = report_data.get("risk_assessment", {})
        
        print(f"\033[93m[REPORT] Run ID:\033[0m {report_data.get('run_id', 'Unknown')}")
        print(f"\033[93m[TARGET] Targets Scanned:\033[0m {exec_summary.get('targets_scanned', 0)}")
        print(f"\033[93m[RECON] Subdomains Found:\033[0m {exec_summary.get('subdomains_discovered', 0)}")
        print(f"\033[93m[PORTS] Open Ports:\033[0m {exec_summary.get('open_ports_found', 0)}")
        print(f"\033[93m🌐 HTTP Services:\033[0m {exec_summary.get('http_services_identified', 0)}")
        
        # Risk assessment
        risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
        risk_color = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[91m',      # Red  
            'MEDIUM': '\033[93m',    # Yellow
            'LOW': '\033[92m',       # Green
            'INFORMATIONAL': '\033[94m'  # Blue
        }.get(risk_level, '\033[0m')
        
        print(f"\n\033[93m[SECURITY] Overall Risk Level:\033[0m {risk_color}{risk_level}\033[0m")
        
        # Severity breakdown
        severity_counts = risk_assessment.get('severity_breakdown', {})
        if any(severity_counts.values()):
            print(f"\n\033[93m[SUMMARY] Vulnerability Breakdown:\033[0m")
            print(f"  [ALERT] Critical: {severity_counts.get('critical', 0)}")
            print(f"  🔴 High: {severity_counts.get('high', 0)}")
            print(f"  🟡 Medium: {severity_counts.get('medium', 0)}")
            print(f"  🟢 Low: {severity_counts.get('low', 0)}")
            print(f"  ℹ️ Info: {severity_counts.get('info', 0)}")
        
        # Key findings
        key_findings = exec_summary.get('key_findings', [])
        if key_findings:
            print(f"\n\033[93m[RECON] Key Findings:\033[0m")
            for finding in key_findings[:5]:  # Show top 5
                print(f"  • {finding}")
        
        # Recommendations
        recommendations = risk_assessment.get('recommendations', [])
        if recommendations:
            print(f"\n\033[93m💡 Top Recommendations:\033[0m")
            for rec in recommendations[:5]:  # Show top 5
                print(f"  • {rec}")
        
        print(f"\n\033[93m📁 Full Report:\033[0m {latest_run / 'report' / 'report.html'}")
        
    except Exception as e:
        logger.log(f"Error generating summary: {e}", "ERROR")
    
    input("\nPress Enter to continue...")

def manage_targets():
    print("\n\033[96m" + "="*80 + "\033[0m")
    print("\033[96mTARGETS".center(80) + "\033[0m")
    print("\033[96m" + "="*80 + "\033[0m")
    print("\033[95m1. View\033[0m")
    print("\033[95m2. Add\033[0m")
    print("\033[95m3. Import from file\033[0m")
    print("\033[95m4. Clear\033[0m")
    print("\033[91m5. Back\033[0m")
    try:
        s = input("\n\033[93mSelect (1-5): \033[0m").strip()
        if s == "1":
            ts = read_lines(TARGETS)
            if not ts:
                print("  No targets.")
            else:
                for t in ts:
                    print(f"  - {t}")
            input("\nEnter to continue...")
        elif s == "2":
            t = input("Enter target (domain or URL): ").strip()
            if t and validate_input(t, max_length=200):
                # Basic domain/URL validation pattern
                import re
                domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
                url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
                
                if re.match(domain_pattern, t) or re.match(url_pattern, t):
                    write_uniq(TARGETS, read_lines(TARGETS) + [t])
                    logger.log("Target added", "SUCCESS")
                else:
                    logger.log("Invalid target format. Use domain.com or http://domain.com", "ERROR")
            elif t:
                logger.log("Invalid or potentially dangerous target input", "ERROR")
        elif s == "3":
            p = input("Path to file: ").strip()
            if p and validate_input(p, max_length=500):
                fp = Path(p)
                if fp.exists() and fp.is_file():
                    write_uniq(TARGETS, read_lines(TARGETS) + read_lines(fp))
                    logger.log("Imported", "SUCCESS")
                else:
                    logger.log("File not found or not a regular file", "ERROR")
            else:
                logger.log("Invalid or potentially dangerous file path", "ERROR")
        elif s == "4":
            if input("Confirm clear? (yes/no): ").strip().lower() == "yes":
                atomic_write(TARGETS, "")
                logger.log("Targets cleared", "SUCCESS")
    except Exception as e:
        logger.log(f"Target mgmt error: {e}", "ERROR")

def refresh_and_merge():
    cfg = load_cfg()
    logger.log("Refreshing sources...", "INFO")
    sources = refresh_external_sources(cfg)
    logger.log("Merging wordlists...", "INFO")
    merge_wordlists(sources["SecLists"], sources["PayloadsAllTheThings"], sources["Wordlists"])
    logger.log("Sources refreshed and wordlists merged.", "SUCCESS")

def run_recon():
    cfg = load_cfg()
    env = env_with_lists()
    rd = new_run()
    stop_event, th = create_resource_monitor_thread(cfg)
    try:
        stage_recon(rd, env, cfg)
        logger.log(f"Recon complete. Run: {rd}", "SUCCESS")
    finally:
        cleanup_resource_monitor(stop_event, th)

def run_vuln():
    cfg = load_cfg()
    env = env_with_lists()
    rd = new_run()
    stop_event, th = create_resource_monitor_thread(cfg)
    try:
        stage_vuln_scan(rd, env, cfg)
        logger.log(f"Vuln scan complete. Run: {rd}", "SUCCESS")
    finally:
        cleanup_resource_monitor(stop_event, th)

def run_report_for_latest():
    cfg = load_cfg()
    env = env_with_lists()
    runs = sorted([d for d in RUNS_DIR.iterdir() if d.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
    if not runs:
        logger.log("No runs to report", "WARNING")
        return
    rd = runs[0]
    stage_report(rd, env, cfg)
    html = rd / "report" / "report.html"
    if html.exists():
        try:
            webbrowser.open(html.as_uri())
        except Exception:
            logger.log(f"Open report: {html}", "INFO")

def plugins_menu():
    print("\n\033[96m" + "="*80 + "\033[0m")
    print("\033[96mPLUGINS".center(80) + "\033[0m")
    print("\033[96m" + "="*80 + "\033[0m")
    print("\033[95m1. List\033[0m")
    print("\033[95m2. Create template\033[0m")
    print("\033[95m3. Execute plugin\033[0m")
    print("\033[91m4. Back\033[0m")
    s = input("\n\033[93mSelect (1-4): \033[0m").strip()
    if s == "1":
        pl = load_plugins()
        if not pl:
            print("  No plugins found.")
        else:
            for name, info in pl.items():
                meta = info.get("info", {})
                print(f"  - {name} :: {meta.get('description','(no desc)')}")
        input("\nEnter to continue...")
    elif s == "2":
        name = input("New plugin name: ").strip()
        if name:
            create_plugin_template(name)
    elif s == "3":
        name = input("Plugin to execute: ").strip()
        if name:
            rd = new_run()
            execute_plugin(name, rd, env_with_lists(), load_cfg())

# ---------- Enhanced Automation Functions ----------
def run_eslint_security_check():
    """Run ESLint security checks on JavaScript files"""
    print("\n\033[96m=== ESLint Security Check ===\033[0m")
    
    try:
        # Check if Node.js and npm are available
        if not shutil.which("npm"):
            logger.log("npm not found. Please install Node.js and npm for ESLint integration", "WARNING")
            input("Press Enter to continue...")
            return
        
        # Install ESLint dependencies if needed
        package_json = HERE / "package.json"
        if package_json.exists():
            logger.log("Installing ESLint dependencies...", "INFO")
            result = safe_execute(
                run_cmd, 
                ["npm", "install"], 
                cwd=str(HERE),
                timeout=120,
                capture=True,
                check_return=False
            )
            
            if result and result.returncode == 0:
                logger.log("ESLint dependencies installed successfully", "SUCCESS")
            else:
                logger.log("Failed to install ESLint dependencies", "WARNING")
        
        # Run ESLint security check
        logger.log("Running ESLint security analysis...", "INFO")
        result = safe_execute(
            run_cmd,
            ["npm", "run", "lint:security"],
            cwd=str(HERE),
            timeout=60,
            capture=True,
            check_return=False
        )
        
        if result:
            if result.returncode == 0:
                logger.log("ESLint security check completed successfully", "SUCCESS")
                if result.stdout:
                    print(f"ESLint Output:\n{result.stdout}")
            else:
                logger.log("ESLint found security issues", "WARNING")
                if result.stderr:
                    print(f"ESLint Issues:\n{result.stderr}")
        
    except Exception as e:
        logger.log(f"ESLint security check error: {e}", "ERROR")
    
    input("Press Enter to continue...")

def run_bug_bounty_automation():
    """Run comprehensive bug bounty automation"""
    print("\n\033[96m=== Bug Bounty Automation ===\033[0m")
    
    try:
        targets = read_lines(TARGETS)
        if not targets:
            logger.log("No targets configured. Please add targets first.", "WARNING")
            input("Press Enter to continue...")
            return
        
        # Get primary target (first one)
        primary_target = targets[0].strip()
        if primary_target.startswith(('http://', 'https://')):
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(primary_target)
            primary_target = parsed.netloc
        
        logger.log(f"Starting bug bounty automation for: {primary_target}", "INFO")
        
        # Check if bug_bounty_commands.sh exists and is executable
        bug_bounty_script = HERE / "bug_bounty_commands.sh"
        if not bug_bounty_script.exists():
            logger.log("bug_bounty_commands.sh not found", "ERROR")
            input("Press Enter to continue...")
            return
        
        # Make sure script is executable
        import stat
        current_perms = bug_bounty_script.stat().st_mode
        bug_bounty_script.chmod(current_perms | stat.S_IEXEC)
        
        # Run bug bounty automation
        logger.log("Executing comprehensive bug bounty reconnaissance...", "INFO")
        
        # Create a new run directory for bug bounty results
        run_dir = new_run()
        
        # Execute the bug bounty script
        result = safe_execute(
            run_cmd,
            [str(bug_bounty_script), primary_target],
            cwd=str(HERE),
            timeout=1800,  # 30 minutes timeout
            capture=True,
            check_return=False
        )
        
        if result:
            if result.returncode == 0:
                logger.log("Bug bounty automation completed successfully", "SUCCESS")
                
                # Copy results to run directory
                bug_bounty_results = HERE / "bug_bounty_results"
                if bug_bounty_results.exists():
                    import shutil as sh
                    sh.copytree(bug_bounty_results, run_dir / "bug_bounty_results", dirs_exist_ok=True)
                    logger.log(f"Results copied to: {run_dir / 'bug_bounty_results'}", "INFO")
                
            else:
                logger.log(f"Bug bounty automation completed with warnings (exit code: {result.returncode})", "WARNING")
            
            # Show summary output
            if result.stdout:
                print(f"\nBug Bounty Summary:\n{result.stdout[-1000:]}")  # Last 1000 chars
        else:
            logger.log("Bug bounty automation failed to execute", "ERROR")
        
    except Exception as e:
        logger.log(f"Bug bounty automation error: {e}", "ERROR")
    
    input("Press Enter to continue...")

def run_automated_testing_chain():
    """Run comprehensive automated testing chain"""
    print("\n\033[96m=== Automated Testing Chain ===\033[0m")
    
    try:
        logger.log("Starting comprehensive automated testing chain...", "INFO")
        
        # Phase 1: ESLint Security Check
        print("\n--- Phase 1: Code Quality & Security ---")
        run_eslint_security_check()
        
        # Phase 2: Enhanced Reconnaissance  
        print("\n--- Phase 2: Enhanced Reconnaissance ---")
        run_enhanced_recon()
        
        # Phase 3: Bug Bounty Automation
        print("\n--- Phase 3: Bug Bounty Automation ---")
        run_bug_bounty_automation()
        
        # Phase 4: Advanced Vulnerability Scanning
        print("\n--- Phase 4: Advanced Vulnerability Scanning ---") 
        run_advanced_vuln_scan()
        
        # Phase 5: AI-Powered Analysis
        print("\n--- Phase 5: AI-Powered Analysis ---")
        run_ai_vulnerability_analysis()
        
        # Phase 6: Generate Comprehensive Report
        print("\n--- Phase 6: Comprehensive Reporting ---")
        generate_enhanced_report()
        
        logger.log("Automated testing chain completed successfully", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Automated testing chain error: {e}", "ERROR")
    
    input("Press Enter to continue...")

def run_enhanced_recon():
    """Run enhanced reconnaissance with additional tools"""
    print("\n\033[96m=== Enhanced Reconnaissance ===\033[0m")
    
    targets = read_lines(TARGETS)
    if not targets:
        logger.log("No targets configured", "WARNING")
        return
        
    rd = new_run()
    env = env_with_lists()
    cfg = load_cfg()
    
    logger.log("Starting enhanced reconnaissance...", "INFO")
    
    # Enhanced subdomain enumeration
    enhanced_subdomain_enum(targets, rd, cfg)
    
    # Enhanced port scanning
    enhanced_port_scanning(targets, rd, cfg)
    
    # Technology detection
    enhanced_tech_detection(targets, rd, cfg)
    
    # Web crawling and URL collection
    enhanced_web_crawling(targets, rd, cfg)
    
    logger.log("Enhanced reconnaissance completed", "SUCCESS")

def enhanced_subdomain_enum(targets, run_dir, cfg):
    """Enhanced subdomain enumeration with multiple tools"""
    logger.log("Running enhanced subdomain enumeration...", "INFO")
    
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        # Use multiple subdomain enumeration tools
        tools = ["subfinder", "amass", "assetfinder"]
        results = []
        
        for tool in tools:
            if shutil.which(tool):
                logger.log(f"Running {tool} for {target}...", "DEBUG")
                
                if tool == "subfinder":
                    result = safe_execute(
                        run_cmd,
                        ["subfinder", "-d", target, "-silent"],
                        capture=True,
                        timeout=300,
                        check_return=False
                    )
                elif tool == "amass":
                    result = safe_execute(
                        run_cmd,
                        ["amass", "enum", "-d", target, "-passive"],
                        capture=True, 
                        timeout=300,
                        check_return=False
                    )
                elif tool == "assetfinder":
                    result = safe_execute(
                        run_cmd,
                        ["assetfinder", "--subs-only", target],
                        capture=True,
                        timeout=300,
                        check_return=False
                    )
                
                if result and result.stdout:
                    results.extend(result.stdout.strip().split('\n'))
        
        # Deduplicate and save results
        if results:
            unique_subdomains = sorted(set(filter(None, results)))
            subdomain_file = run_dir / f"subdomains_{target.replace('.', '_')}.txt"
            write_lines(subdomain_file, unique_subdomains)
            logger.log(f"Found {len(unique_subdomains)} subdomains for {target}", "SUCCESS")

def enhanced_port_scanning(targets, run_dir, cfg):
    """Enhanced port scanning with multiple tools"""
    logger.log("Running enhanced port scanning...", "INFO")
    
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        # Use nmap for comprehensive port scanning
        if shutil.which("nmap"):
            logger.log(f"Running nmap scan for {target}...", "DEBUG")
            
            # Top 1000 ports scan
            result = safe_execute(
                run_cmd,
                ["nmap", "-T4", "-top-ports", "1000", "--open", "-oG", "-", target],
                capture=True,
                timeout=600,
                check_return=False
            )
            
            if result and result.stdout:
                ports_file = run_dir / f"ports_{target.replace('.', '_')}.txt"
                with open(ports_file, 'w') as f:
                    f.write(result.stdout)
                logger.log(f"Port scan completed for {target}", "SUCCESS")

def enhanced_tech_detection(targets, run_dir, cfg):
    """Enhanced technology detection"""
    logger.log("Running enhanced technology detection...", "INFO")
    
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        # Use httpx for technology detection
        if shutil.which("httpx"):
            result = safe_execute(
                run_cmd,
                ["httpx", "-u", target, "-tech-detect", "-title", "-silent"],
                capture=True,
                timeout=60,
                check_return=False
            )
            
            if result and result.stdout:
                tech_file = run_dir / f"tech_{target.replace('://', '_').replace('.', '_')}.txt"
                with open(tech_file, 'w') as f:
                    f.write(result.stdout)

def enhanced_web_crawling(targets, run_dir, cfg):
    """Enhanced web crawling for URL collection"""
    logger.log("Running enhanced web crawling...", "INFO")
    
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        # Use multiple crawling tools
        all_urls = set()
        
        # GAU - Get All URLs
        if shutil.which("gau"):
            result = safe_execute(
                run_cmd,
                ["gau", target],
                capture=True,
                timeout=120,
                check_return=False
            )
            if result and result.stdout:
                all_urls.update(result.stdout.strip().split('\n'))
        
        # Waybackurls
        if shutil.which("waybackurls"):
            result = safe_execute(
                run_cmd,
                ["waybackurls", target],
                capture=True,
                timeout=120,
                check_return=False
            )
            if result and result.stdout:
                all_urls.update(result.stdout.strip().split('\n'))
        
        # Save collected URLs
        if all_urls:
            filtered_urls = [url for url in all_urls if url and url.startswith(('http://', 'https://'))]
            if filtered_urls:
                urls_file = run_dir / f"urls_{target.replace('.', '_')}.txt"
                write_lines(urls_file, sorted(filtered_urls))
                logger.log(f"Collected {len(filtered_urls)} URLs for {target}", "SUCCESS")

# ---------- Enhanced Menu Functions ----------
def run_ai_vulnerability_analysis():
    """Run AI-powered vulnerability analysis"""
    print("\n\033[96m=== AI-Powered Vulnerability Analysis ===\033[0m")
    
    try:
        # Find latest scan results
        runs = sorted([d for d in RUNS_DIR.iterdir() if d.is_dir()], 
                     key=lambda p: p.stat().st_mtime, reverse=True)
        
        if not runs:
            logger.log("No scan results found. Please run a vulnerability scan first.", "WARNING")
            input("Press Enter to continue...")
            return
        
        latest_run = runs[0]
        logger.log(f"Analyzing results from: {latest_run.name}", "INFO")
        
        # Run ML-based analysis
        cfg = load_cfg()
        ml_out = latest_run / "ai_analysis_results.json"
        
        run_ml_vulnerability_analysis(latest_run, ml_out, cfg)
        
        # Display results
        if ml_out.exists():
            with open(ml_out, 'r') as f:
                results = json.load(f)
            
            print(f"\n[REPORT] AI Analysis Results:")
            print(f"   False Positive Reduction: {results.get('false_positive_reduction', {}).get('reduction_percentage', 0):.1f}%")
            print(f"   Risk Level: {results.get('risk_scoring', {}).get('risk_level', 'unknown').upper()}")
            print(f"   Total Risk Score: {results.get('risk_scoring', {}).get('total_risk_score', 0)}")
        
        logger.log("AI vulnerability analysis completed", "SUCCESS")
        
    except Exception as e:
        logger.log(f"AI analysis error: {e}", "ERROR")
    
    input("Press Enter to continue...")

def run_cloud_security_assessment():
    """Run cloud security assessment"""
    print("\n\033[96m=== Cloud Security Assessment ===\033[0m")
    
    try:
        targets = read_lines(TARGETS)
        if not targets:
            logger.log("No targets configured", "WARNING")
            input("Press Enter to continue...")
            return
        
        # Load and execute cloud security scanner plugin
        plugins = load_plugins()
        if "cloud_security_scanner" not in plugins:
            logger.log("Cloud security scanner plugin not found", "WARNING")
            input("Press Enter to continue...")
            return
        
        run_dir = new_run()
        env = env_with_lists()
        cfg = load_cfg()
        
        logger.log("Starting cloud security assessment...", "INFO")
        plugins["cloud_security_scanner"]["execute"](run_dir, env, cfg)
        
        logger.log("Cloud security assessment completed", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Cloud security assessment error: {e}", "ERROR")
    
    input("Press Enter to continue...")

def run_api_security_testing():
    """Run API security testing"""
    print("\n\033[96m=== API Security Testing ===\033[0m")
    
    try:
        targets = read_lines(TARGETS)
        if not targets:
            logger.log("No targets configured", "WARNING")
            input("Press Enter to continue...")
            return
        
        # Load and execute API security scanner plugin
        plugins = load_plugins()
        if "api_security_scanner" not in plugins:
            logger.log("API security scanner plugin not found", "WARNING")
            input("Press Enter to continue...")
            return
        
        run_dir = new_run()
        env = env_with_lists()
        cfg = load_cfg()
        
        logger.log("Starting API security testing...", "INFO")
        plugins["api_security_scanner"]["execute"](run_dir, env, cfg)
        
        logger.log("API security testing completed", "SUCCESS")
        
    except Exception as e:
        logger.log(f"API security testing error: {e}", "ERROR")
    
    input("Press Enter to continue...")

def run_compliance_assessment():
    """Run compliance and risk assessment"""
    print("\n\033[96m=== Compliance & Risk Assessment ===\033[0m")
    
    try:
        targets = read_lines(TARGETS)
        if not targets:
            logger.log("No targets configured", "WARNING")
            input("Press Enter to continue...")
            return
        
        run_dir = new_run()
        env = env_with_lists()
        cfg = load_cfg()
        
        logger.log("Starting compliance assessment...", "INFO")
        
        # Run compliance checks for each target
        for target in targets:
            target_url = target if target.startswith("http") else f"http://{target}"
            compliance_out = run_dir / f"compliance_{target.replace('.', '_').replace('/', '_')}.json"
            
            run_compliance_checks(target_url, compliance_out, cfg, env)
        
        logger.log("Compliance assessment completed", "SUCCESS")
        
    except Exception as e:
        logger.log(f"Compliance assessment error: {e}", "ERROR")
    
    input("Press Enter to continue...")

def run_cicd_integration_mode():
    """Run CI/CD integration mode"""
    print("\n\033[96m=== CI/CD Integration Mode ===\033[0m")
    
    try:
        print("This mode provides automated security scanning for CI/CD pipelines.")
        print("\nAvailable options:")
        print("1. Quick Scan (Fast, essential vulnerabilities)")
        print("2. Full Scan (Comprehensive security assessment)")
        print("3. API-Only Scan (Focus on API security)")
        print("4. Cloud-Only Scan (Focus on cloud security)")
        print("5. Generate CI/CD Configuration Files")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == "5":
            # Display info about generated CI/CD files
            logger.log("CI/CD configuration files have been generated", "SUCCESS")
            
            print("\nGenerated files:")
            print("📁 .github/workflows/security_scan.yml - GitHub Actions workflow")
            print("🐳 Dockerfile - Container for deployment")
            print("[START] cicd_integration.py - CI/CD integration script")
            
            print("\nUsage examples:")
            print("# CLI usage:")
            print("python3 cicd_integration.py --target example.com --scan-type quick")
            print("\n# Docker usage:")
            print("docker build -t bl4ckc3ll-pantheon .")
            print("docker run bl4ckc3ll-pantheon")
            
        elif choice in ["1", "2", "3", "4"]:
            targets = read_lines(TARGETS)
            if not targets:
                logger.log("No targets configured", "WARNING")
                input("Press Enter to continue...")
                return
            
            scan_types = {"1": "quick", "2": "full", "3": "api-only", "4": "cloud-only"}
            scan_type = scan_types[choice]
            
            logger.log(f"CI/CD {scan_type} scan mode configured", "SUCCESS")
            logger.log("Use cicd_integration.py for automated scanning", "INFO")
        
    except Exception as e:
        logger.log(f"CI/CD integration error: {e}", "ERROR")
    
    input("Press Enter to continue...")

# ---------- Main ----------
def main():
    ensure_layout()
    print(BANNER)
    print(f"\033[91m{APP} v{VERSION}-ENHANCED\033[0m by {AUTHOR}")
    print(f"\033[93m[SECURITY] Advanced Security Testing Framework with Enhanced Capabilities 🛡️\033[0m")
    
    # Validate dependencies and environment
    if not validate_dependencies():
        logger.log("[WARNING] Some dependencies missing. Please run install.sh or install manually.", "WARNING")
        logger.log("Continuing with available functionality...", "WARNING")
        time.sleep(2)
    
    if not check_and_setup_environment():
        logger.log("Environment setup issues detected. Some features may not work correctly.", "WARNING")
        time.sleep(1)
    
    while True:
        display_menu()
        c = get_choice()
        if c == 1:
            manage_targets()
        elif c == 2:
            refresh_and_merge()
        elif c == 3:
            run_recon()
        elif c == 4:
            run_vuln()
        elif c == 5:
            run_full_pipeline()
        elif c == 6:
            run_report_for_latest()
        elif c == 7:
            settings_menu()
        elif c == 8:
            plugins_menu()
        elif c == 9:
            view_last_report()
        elif c == 10:
            network_tools_menu()
        elif c == 11:
            security_assessment_summary()
        elif c == 12:
            run_ai_vulnerability_analysis()
        elif c == 13:
            run_cloud_security_assessment()
        elif c == 14:
            run_api_security_testing()
        elif c == 15:
            run_compliance_assessment()
        elif c == 16:
            run_cicd_integration_mode()
        elif c == 17:
            run_eslint_security_check()
        elif c == 18:
            run_bug_bounty_automation()
        elif c == 19:
            run_automated_testing_chain()
        elif c == 20:
            launch_advanced_tui()
        elif c == 21:
            logger.log("Goodbye! Stay secure!", "INFO")
            break

def launch_advanced_tui():
    """Launch the advanced Terminal User Interface"""
    try:
        logger.log("Launching Advanced TUI Interface...", "INFO")
        import subprocess
        
        # Launch the TUI in a subprocess
        tui_script = HERE / "tui_launcher.py"
        if tui_script.exists():
            subprocess.run([sys.executable, str(tui_script)])
        else:
            logger.log("TUI launcher not found. Using fallback import method.", "WARNING")
            
            # Try direct import
            try:
                from tui.app import PantheonTUI
                app = PantheonTUI()
                app.run()
            except ImportError:
                logger.log("TUI dependencies missing. Install with: pip install textual", "ERROR")
            except Exception as e:
                logger.log(f"TUI launch failed: {e}", "ERROR")
                
    except Exception as e:
        logger.log(f"Failed to launch TUI: {e}", "ERROR")
    
    input("Press Enter to continue...")

def view_last_report():
    """View the last generated report"""
    try:
        runs = sorted([d for d in RUNS_DIR.iterdir() if d.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
        if not runs:
            logger.log("No reports found", "WARNING")
            return
        
        latest_run = runs[0]
        html_report = latest_run / "report" / "report.html"
        
        if html_report.exists():
            try:
                webbrowser.open(html_report.as_uri())
                logger.log("[REPORT] Report opened in browser", "SUCCESS")
            except Exception:
                logger.log(f"[REPORT] View report at: {html_report}", "INFO")
        else:
            logger.log("HTML report not found, generating...", "WARNING")
            run_report_for_latest()
            
    except Exception as e:
        logger.log(f"Error viewing report: {e}", "ERROR")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.log("Interrupted by user", "INFO")
    except Exception as e:
        logger.log(f"Fatal error: {e}", "ERROR")
        sys.exit(1)