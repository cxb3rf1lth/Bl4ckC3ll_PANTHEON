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
        "WebShells": "https://github.com/tennc/webshell.git"
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
        "disable_cluster_bomb": False
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
        "security_headers": True
    },
    "fuzzing": {
        "enable_dirb": True,
        "enable_gobuster": True,
        "enable_ffuf": True,
        "wordlist_size": "medium",
        "extensions": "php,asp,aspx,jsp,html,htm,txt,bak,old,conf"
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
        "cpu_threshold": 85,
        "memory_threshold": 90,
        "disk_threshold": 95,
        "monitor_interval": 5,
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

# ---------- Utils ----------
def _bump_path():
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

def atomic_write(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=path.parent, encoding="utf-8") as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)

def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    for l in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = l.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out

def write_uniq(path: Path, items: List[str]):
    seen = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    atomic_write(path, "\n".join(out) + ("\n" if out else ""))

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
    ensure_layout()
    try:
        return json.loads(CFG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return DEFAULT_CFG.copy()

def save_cfg(cfg: Dict[str, Any]):
    atomic_write(CFG_FILE, json.dumps(cfg, indent=2))

def which(tool: str) -> bool:
    return shutil.which(tool) is not None

# ---------- Dependency validation ----------
def validate_dependencies() -> bool:
    """Validate all dependencies and provide helpful error messages"""
    logger.log("Validating dependencies...", "INFO")
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 9):
        logger.log(f"Python 3.9+ required, found {python_version.major}.{python_version.minor}", "ERROR")
        return False
    
    # Check optional Python packages
    missing_packages = []
    
    try:
        import psutil
        logger.log("psutil available for system monitoring", "DEBUG")
    except ImportError:
        missing_packages.append("psutil")
    
    try:
        import distro
        logger.log("distro available for OS detection", "DEBUG")
    except ImportError:
        missing_packages.append("distro")
    
    try:
        import requests
        logger.log("requests available for HTTP operations", "DEBUG")
    except ImportError:
        missing_packages.append("requests")
    
    if missing_packages:
        logger.log(f"Optional packages missing: {', '.join(missing_packages)}", "WARNING")
        logger.log("Install with: pip3 install " + " ".join(missing_packages), "INFO")
        logger.log("Or run: pip3 install -r requirements.txt", "INFO")
    
    # Check security tools (core + enhanced)
    tools = {
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
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "gospider": "go install github.com/jaeles-project/gospider@latest",
        "subjack": "go install github.com/haccer/subjack@latest",
        "whatweb": "apt install whatweb",
        "wappalyzer": "npm install -g wappalyzer",
        "nikto": "apt install nikto",
        "sqlmap": "apt install sqlmap",
        "commix": "apt install commix"
    }
    
    available_tools = []
    missing_tools = []
    core_tools = ["subfinder", "httpx", "naabu", "nuclei", "katana", "gau"]
    
    for tool, install_cmd in tools.items():
        if which(tool):
            available_tools.append(tool)
            logger.log(f"✓ {tool} available", "DEBUG")
        else:
            missing_tools.append((tool, install_cmd))
    
    logger.log(f"Security tools available: {len(available_tools)}/{len(tools)}", "INFO")
    
    # Check if core tools are available
    core_available = sum(1 for tool in core_tools if which(tool))
    logger.log(f"Core tools available: {core_available}/{len(core_tools)}", "INFO")
    
    if missing_tools:
        logger.log("Missing security tools:", "WARNING")
        for tool, install_cmd in missing_tools:
            if tool in core_tools:
                logger.log(f"  \033[91m{tool}\033[0m (CORE): {install_cmd}", "WARNING")
            else:
                logger.log(f"  \033[93m{tool}\033[0m (ENHANCED): {install_cmd}", "WARNING")
        logger.log("Run the install.sh script to automatically install missing tools", "INFO")
    
    # Check essential system tools
    essential_tools = ["git", "wget", "unzip", "curl", "dig", "whois"]
    missing_essential = []
    
    for tool in essential_tools:
        if not which(tool):
            missing_essential.append(tool)
    
    if missing_essential:
        logger.log(f"Essential system tools missing: {', '.join(missing_essential)}", "ERROR")
        logger.log("Please install missing system tools using your package manager", "ERROR")
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
    while not stop_event.is_set():
        r = get_system_resources()
        logger.log(f"Resources CPU:{r['cpu']:.1f}% MEM:{r['memory']:.1f}% DISK:{r['disk']:.1f}%", "DEBUG")
        if r["cpu"] > cfg["resource_management"]["cpu_threshold"] or \
           r["memory"] > cfg["resource_management"]["memory_threshold"] or \
           r["disk"] > cfg["resource_management"]["disk_threshold"]:
            logger.log("High resource usage, slowing down...", "WARNING")
            time.sleep(cfg["resource_management"]["monitor_interval"] * 2)
        else:
            time.sleep(cfg["resource_management"]["monitor_interval"])

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
        "Wordlists": EXT_DIR / "Probable-Wordlists",
    }
    for name, path in sources.items():
        url = cfg["repos"].get(name)
        if not url:
            continue
        git_clone_or_pull(url, path)
        if not path.exists() and cfg["fallback"]["enabled"] and cfg["fallback"]["direct_downloads"]:
            logger.log(f"Trying direct download fallback for {name}", "WARNING")
            direct_zip_download(url, path)
    return sources

def merge_wordlists(seclists_path: Path, payloads_path: Path, probable_wordlists_path: Path):
    logger.log("Merging wordlists...", "INFO")
    MERGED_DIR.mkdir(parents=True, exist_ok=True)
    all_files: List[Path] = []
    for base in [seclists_path, payloads_path, probable_wordlists_path, EXTRA_DIR]:
        if base.exists():
            for root, _, files in os.walk(base):
                for f in files:
                    if f.endswith((".txt", ".dic", ".lst")):
                        all_files.append(Path(root) / f)
    merged_file = MERGED_DIR / "all_merged_wordlist.txt"
    uniq = set()
    for fp in all_files:
        try:
            for line in fp.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s and not s.startswith("#") and len(s) < 512:
                    uniq.add(s)
        except Exception as e:
            logger.log(f"Read error {fp}: {e}", "WARNING")
    atomic_write(merged_file, "\n".join(sorted(uniq)))
    logger.log(f"Merged {len(uniq)} unique lines -> {merged_file}", "SUCCESS")

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

def run_sqlmap(target: str, out_file: Path, env: Dict[str, str]):
    if not which("sqlmap"):
        logger.log("sqlmap not found, skipping", "WARNING")
        return
    run_cmd([
        "sqlmap", "-u", target, "--batch", "--crawl", "2",
        "--level", "3", "--risk", "2", "--output-dir", str(out_file.parent),
        "--technique", "BEUST", "--threads", "5"
    ], env=env, timeout=1800, check_return=False)

def run_nuclei_single_target(target: str, out_file: Path, cfg: Dict[str, Any], env: Dict[str, str]):
    if not which("nuclei") or not cfg["nuclei"]["enabled"]:
        logger.log("nuclei not found or disabled, skipping", "WARNING")
        return
    cmd = [
        "nuclei", "-u", target, "-json", "-o", str(out_file),
        "-severity", cfg["nuclei"]["severity"],
        "-rl", str(cfg["nuclei"]["rps"]),
        "-c", str(cfg["nuclei"]["conc"]),
        "-silent", "-no-color"
    ]
    if cfg["nuclei"]["all_templates"]:
        # default template path commonly at ~/nuclei-templates
        tpl = str(Path.home() / "nuclei-templates")
        if Path(tpl).exists():
            cmd.extend(["-t", tpl])
    
    # Add custom templates if enabled
    if cfg["nuclei"].get("custom_templates", False):
        custom_templates = PLUGINS_DIR / "nuclei_templates"
        if custom_templates.exists():
            cmd.extend(["-t", str(custom_templates)])
    
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
            
            # Phase 5: SQL Injection Testing (if enabled)
            if which("sqlmap") and cfg.get("advanced_scanning", {}).get("sql_injection", False):
                logger.log(f"Phase 5: SQL injection testing for {target}", "INFO")
                sqlmap_out = tdir / "sqlmap_results"
                sqlmap_out.mkdir(exist_ok=True)
                run_sqlmap(target_url, sqlmap_out, env)
            
            # Phase 6: Check for common vulnerabilities from recon data
            logger.log(f"Phase 6: Additional vulnerability checks for {target}", "INFO")
            additional_out = tdir / "additional_vulns.json"
            perform_additional_checks(target, tdir, additional_out, cfg, env)
            
            logger.log(f"Vulnerability scanning completed for {target}", "SUCCESS")
            
        except Exception as e:
            logger.log(f"Vulnerability scan error {target}: {e}", "ERROR")

    with ThreadPoolExecutor(max_workers=cfg["limits"]["max_concurrent_scans"]) as ex:
        futs = [ex.submit(per_target, t) for t in targets]
        for _ in as_completed(futs):
            pass

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

def perform_additional_checks(target: str, target_dir: Path, out_file: Path, cfg: Dict[str, Any], env: Dict[str, str]):
    """Perform additional vulnerability checks based on discovered services"""
    additional_vulns = {
        "target": target,
        "checks_performed": [],
        "vulnerabilities": [],
        "recommendations": []
    }
    
    try:
        # Check for common admin panels
        admin_paths = [
            "/admin", "/administrator", "/admin.php", "/admin/login.php",
            "/wp-admin", "/administrator/", "/admin/index.php", "/admin/admin.php",
            "/login", "/login.php", "/signin", "/signin.php"
        ]
        
        if which("curl"):
            additional_vulns["checks_performed"].append("Admin panel discovery")
            found_panels = []
            
            for path in admin_paths:
                full_url = target.rstrip('/') + path
                try:
                    result = run_cmd(["curl", "-I", "-s", "-k", "-m", "10", full_url], 
                                   capture=True, timeout=15, check_return=False)
                    if result.stdout and ("200 OK" in result.stdout or "302 Found" in result.stdout):
                        found_panels.append(path)
                except Exception:
                    continue
            
            if found_panels:
                additional_vulns["vulnerabilities"].append({
                    "type": "Exposed Admin Panels",
                    "severity": "medium",
                    "description": f"Found {len(found_panels)} potential admin panels",
                    "details": found_panels
                })
        
        # Check for common backup files
        backup_extensions = [".bak", ".backup", ".old", ".orig", ".save", ".tmp"]
        common_files = ["index", "config", "database", "db", "admin", "login"]
        
        additional_vulns["checks_performed"].append("Backup file discovery")
        found_backups = []
        
        if which("curl"):
            for file in common_files:
                for ext in backup_extensions:
                    backup_url = f"{target.rstrip('/')}/{file}{ext}"
                    try:
                        result = run_cmd(["curl", "-I", "-s", "-k", "-m", "5", backup_url], 
                                       capture=True, timeout=10, check_return=False)
                        if result.stdout and "200 OK" in result.stdout:
                            found_backups.append(f"{file}{ext}")
                    except Exception:
                        continue
        
        if found_backups:
            additional_vulns["vulnerabilities"].append({
                "type": "Exposed Backup Files",
                "severity": "high",
                "description": f"Found {len(found_backups)} potential backup files",
                "details": found_backups
            })
        
        # Check robots.txt for sensitive information
        additional_vulns["checks_performed"].append("Robots.txt analysis")
        if which("curl"):
            try:
                robots_url = f"{target.rstrip('/')}/robots.txt"
                result = run_cmd(["curl", "-s", "-k", "-m", "10", robots_url], 
                               capture=True, timeout=15, check_return=False)
                if result.stdout and "disallow" in result.stdout.lower():
                    disallowed = []
                    for line in result.stdout.split('\n'):
                        if line.lower().startswith('disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                disallowed.append(path)
                    
                    if disallowed:
                        additional_vulns["vulnerabilities"].append({
                            "type": "Robots.txt Information Disclosure",
                            "severity": "low",
                            "description": "Robots.txt reveals potentially sensitive paths",
                            "details": disallowed[:10]  # Limit to first 10
                        })
            except Exception:
                pass
        
        # Generate recommendations based on findings
        if additional_vulns["vulnerabilities"]:
            additional_vulns["recommendations"].extend([
                "Review and secure exposed admin panels",
                "Remove or protect backup files",
                "Implement proper access controls",
                "Regular security assessments"
            ])
        
        atomic_write(out_file, json.dumps(additional_vulns, indent=2))
        
    except Exception as e:
        logger.log(f"Additional checks error: {e}", "WARNING")

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
    
    for target, data in vuln_results.items():
        total_score += data.get("risk_score", 0)
        nuclei_parsed = data.get("nuclei_parsed", {})
        for severity, findings in nuclei_parsed.items():
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
        recommendations.append("🚨 IMMEDIATE ACTION REQUIRED: Critical vulnerabilities found")
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
            findings.append(f"🚨 {target}: {len(nuclei_parsed['critical'])} critical vulnerabilities")
        
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
                tech_info = f"<h5>🔧 Technology Stack</h5><pre>{esc(json.dumps(data['technology_stack'], indent=2)[:500])}</pre>"
            
            # Network info
            network_info = ""
            if data.get("network_info"):
                network_info = "<h5>🌐 Network Information</h5>"
                for key, value in data["network_info"].items():
                    network_info += f"<h6>{esc(key.title())}</h6><pre>{esc(str(value)[:300])}</pre>"
            
            chunks.append(f"""
            <div class="target-section">
              <h3>🎯 Target: {esc(target)}</h3>
              <div class="info-grid">
                <div class="info-box">
                  <h4>🔍 Subdomains ({len(data['subdomains'])})</h4>
                  <ul class="subdomain-list">{subs}</ul>
                </div>
                <div class="info-box">
                  <h4>🔌 Open Ports ({len(data['open_ports'])})</h4>
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
                  <h4>📊 Vulnerability Summary</h4>
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
                    findings_html += f"<h5 class='severity-header {severity}'>🚨 {severity.title()} ({len(findings)})</h5>"
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
              <h3>🎯 Target: {esc(target)}</h3>
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
      <h2>📈 Executive Summary</h2>
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
        <h3>🔍 Key Findings</h3>
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
  <title>🛡️ Penetration Test Report - {esc(report_data['run_id'])}</title>
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
    <h1>🛡️ Bl4ckC3ll_PANTHEON Security Assessment</h1>
    <p><strong>Run ID:</strong> {esc(report_data['run_id'])}</p>
    <p><strong>Generated:</strong> {esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
  </div>

  {summary_html}

  <div class="section">
    <h2>🎯 Target Information</h2>
    <ul>{"".join(f"<li><strong>{esc(t)}</strong></li>" for t in report_data["targets"])}</ul>
  </div>

  <div class="section">
    <h2>🔍 Reconnaissance Results</h2>
    {html_recon()}
  </div>

  <div class="section">
    <h2>🚨 Vulnerability Assessment</h2>
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
    print("\033[93m1. 🎯 Manage Targets\033[0m")
    print("\033[93m2. 🔄 Refresh Sources + Merge Wordlists\033[0m")
    print("\033[93m3. 🔍 Enhanced Reconnaissance\033[0m")
    print("\033[93m4. 🚨 Advanced Vulnerability Scan\033[0m")
    print("\033[93m5. 🔗 Full Pipeline (Recon + Vuln + Report)\033[0m")
    print("\033[93m6. 📊 Generate Enhanced Report\033[0m")
    print("\033[93m7. 🔧 Settings & Configuration\033[0m")
    print("\033[93m8. 🔌 Plugins Management\033[0m")
    print("\033[93m9. 📈 View Last Report\033[0m")
    print("\033[93m10. 🧪 Network Analysis Tools\033[0m")
    print("\033[93m11. 🛡️ Security Assessment Summary\033[0m")
    print("\033[91m12. 🚪 Exit\033[0m")
    print("\033[31m" + "="*80 + "\033[0m")

def get_choice() -> int:
    try:
        s = input("\n\033[93mSelect (1-12): \033[0m").strip()
        if s.isdigit():
            n = int(s)
            if 1 <= n <= 12:
                return n
    except (EOFError, KeyboardInterrupt):
        return 12
    except Exception:
        pass
    return 12

def run_full_pipeline():
    """Run the complete pipeline: recon -> vuln scan -> report"""
    cfg = load_cfg()
    env = env_with_lists()
    rd = new_run()
    stop_event = threading.Event()
    th = threading.Thread(target=resource_monitor, args=(cfg, stop_event), daemon=True)
    th.start()
    
    try:
        logger.log("🚀 Starting full security assessment pipeline", "INFO")
        
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
                    logger.log("📊 Report opened in browser", "SUCCESS")
                except Exception:
                    logger.log(f"📊 View report at: {html_report}", "INFO")
        
    finally:
        stop_event.set()
        th.join()

def settings_menu():
    """Enhanced settings and configuration menu"""
    while True:
        print("\n\033[31m" + "="*80 + "\033[0m")
        print("\033[91m" + "SETTINGS & CONFIGURATION".center(80) + "\033[0m")
        print("\033[31m" + "="*80 + "\033[0m")
        print("\033[93m1. 🔧 View Current Configuration\033[0m")
        print("\033[93m2. ⚙️ Scan Settings\033[0m")
        print("\033[93m3. 📊 Report Settings\033[0m")
        print("\033[93m4. 🌐 Network Settings\033[0m")
        print("\033[93m5. 🛡️ Security Settings\033[0m")
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
                if input("\n⚠️ Reset all settings to defaults? (yes/no): ").lower() == "yes":
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
        print("\033[93m2. 🔍 DNS Enumeration\033[0m")
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
        
        print(f"\033[93m📊 Run ID:\033[0m {report_data.get('run_id', 'Unknown')}")
        print(f"\033[93m🎯 Targets Scanned:\033[0m {exec_summary.get('targets_scanned', 0)}")
        print(f"\033[93m🔍 Subdomains Found:\033[0m {exec_summary.get('subdomains_discovered', 0)}")
        print(f"\033[93m🔌 Open Ports:\033[0m {exec_summary.get('open_ports_found', 0)}")
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
        
        print(f"\n\033[93m🛡️ Overall Risk Level:\033[0m {risk_color}{risk_level}\033[0m")
        
        # Severity breakdown
        severity_counts = risk_assessment.get('severity_breakdown', {})
        if any(severity_counts.values()):
            print(f"\n\033[93m📈 Vulnerability Breakdown:\033[0m")
            print(f"  🚨 Critical: {severity_counts.get('critical', 0)}")
            print(f"  🔴 High: {severity_counts.get('high', 0)}")
            print(f"  🟡 Medium: {severity_counts.get('medium', 0)}")
            print(f"  🟢 Low: {severity_counts.get('low', 0)}")
            print(f"  ℹ️ Info: {severity_counts.get('info', 0)}")
        
        # Key findings
        key_findings = exec_summary.get('key_findings', [])
        if key_findings:
            print(f"\n\033[93m🔍 Key Findings:\033[0m")
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
            if t:
                write_uniq(TARGETS, read_lines(TARGETS) + [t])
                logger.log("Target added", "SUCCESS")
        elif s == "3":
            p = input("Path to file: ").strip()
            fp = Path(p)
            if fp.exists():
                write_uniq(TARGETS, read_lines(TARGETS) + read_lines(fp))
                logger.log("Imported", "SUCCESS")
            else:
                logger.log("File not found", "ERROR")
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
    stop_event = threading.Event()
    th = threading.Thread(target=resource_monitor, args=(cfg, stop_event), daemon=True)
    th.start()
    try:
        stage_recon(rd, env, cfg)
        logger.log(f"Recon complete. Run: {rd}", "SUCCESS")
    finally:
        stop_event.set()
        th.join()

def run_vuln():
    cfg = load_cfg()
    env = env_with_lists()
    rd = new_run()
    stop_event = threading.Event()
    th = threading.Thread(target=resource_monitor, args=(cfg, stop_event), daemon=True)
    th.start()
    try:
        stage_vuln_scan(rd, env, cfg)
        logger.log(f"Vuln scan complete. Run: {rd}", "SUCCESS")
    finally:
        stop_event.set()
        th.join()

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

# ---------- Main ----------
def main():
    ensure_layout()
    print(BANNER)
    print(f"\033[91m{APP} v{VERSION}-ENHANCED\033[0m by {AUTHOR}")
    print(f"\033[93m🛡️ Advanced Security Testing Framework with Enhanced Capabilities 🛡️\033[0m")
    
    # Validate dependencies and environment
    if not validate_dependencies():
        logger.log("⚠️ Some dependencies missing. Please run install.sh or install manually.", "WARNING")
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
            logger.log("🚪 Goodbye! Stay secure! 🛡️", "INFO")
            break

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
                logger.log("📊 Report opened in browser", "SUCCESS")
            except Exception:
                logger.log(f"📊 View report at: {html_report}", "INFO")
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