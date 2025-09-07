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
        "Wordlists": "https://github.com/berzerk0/Probable-Wordlists.git"
    },
    "limits": {
        "parallel_jobs": 20,
        "http_timeout": 15,
        "rps": 500,
        "max_concurrent_scans": 8,
        "http_revalidation_timeout": 8
    },
    "nuclei": {
        "enabled": True,
        "severity": "low,medium,high,critical",
        "rps": 800,
        "conc": 150,
        "all_templates": True,
        "keep_info_severity": False
    },
    "endpoints": {
        "use_gau": True,
        "use_katana": True,
        "max_urls_per_target": 5000,
        "katana_depth": 2
    },
    "report": {
        "formats": ["html", "json", "csv"],
        "auto_open_html": True,
        "include_viz": True
    },
    "plugins": {
        "enabled": True,
        "directory": str(PLUGINS_DIR)
    },
    "fallback": {
        "enabled": True,
        "direct_downloads": True
    },
    "resource_management": {
        "cpu_threshold": 85,
        "memory_threshold": 90,
        "disk_threshold": 95,
        "monitor_interval": 5
    },
    "error_handling": {
        "max_retries": 3,
        "retry_delay": 2,
        "continue_on_error": True,
        "log_level": "INFO"
    },
    "validation": {
        "validate_tools_on_startup": True,
        "check_dependencies": True,
        "warn_on_missing_tools": True
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
    
    if missing_packages:
        logger.log(f"Optional packages missing: {', '.join(missing_packages)}", "WARNING")
        logger.log("Install with: pip3 install " + " ".join(missing_packages), "INFO")
        logger.log("Or run: pip3 install -r requirements.txt", "INFO")
    
    # Check security tools
    tools = {
        "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest", 
        "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "gau": "github.com/lc/gau/v2/cmd/gau@latest"
    }
    
    available_tools = []
    missing_tools = []
    
    for tool, install_cmd in tools.items():
        if which(tool):
            available_tools.append(tool)
            logger.log(f"✓ {tool} available", "DEBUG")
        else:
            missing_tools.append((tool, install_cmd))
    
    logger.log(f"Security tools available: {len(available_tools)}/{len(tools)}", "INFO")
    
    if missing_tools:
        logger.log("Missing security tools:", "WARNING")
        for tool, install_cmd in missing_tools:
            logger.log(f"  {tool}: go install {install_cmd}", "WARNING")
        logger.log("Run the install.sh script to automatically install missing tools", "INFO")
    
    # Check essential system tools
    essential_tools = ["git", "wget", "unzip"]
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
    return True

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
    run_cmd(["subfinder", "-d", domain, "-silent", "-o", str(out_file)], env=env, timeout=600, check_return=False)

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
    run_cmd(["naabu", "-host", host, "-p", "-", "-rate", str(rps), "-o", str(out_file)], env=env, timeout=1200, check_return=False)

def run_httpx(input_file: Path, out_file: Path, env: Dict[str, str], http_timeout: int):
    if not which("httpx"):
        logger.log("httpx not found, skipping", "WARNING")
        return
    run_cmd([
        "httpx", "-l", str(input_file), "-o", str(out_file),
        "-silent", "-follow-redirects",
        "-mc", "200,201,202,204,301,302,303,307,308,401,403,405,500",
        "-json", "-title", "-tech-detect", "-sc", "-timeout", str(http_timeout)
    ], env=env, timeout=1200, check_return=False)

def run_nuclei_single_target(target: str, out_file: Path, cfg: Dict[str, Any], env: Dict[str, str]):
    if not which("nuclei") or not cfg["nuclei"]["enabled"]:
        logger.log("nuclei not found or disabled, skipping", "WARNING")
        return
    cmd = [
        "nuclei", "-u", target, "-json", "-o", str(out_file),
        "-severity", cfg["nuclei"]["severity"],
        "-rl", str(cfg["nuclei"]["rps"]),
        "-c", str(cfg["nuclei"]["conc"]),
        "-silent"
    ]
    if cfg["nuclei"]["all_templates"]:
        # default template path commonly at ~/nuclei-templates
        tpl = str(Path.home() / "nuclei-templates")
        if Path(tpl).exists():
            cmd.extend(["-t", tpl])
    run_cmd(cmd, env=env, timeout=3600, check_return=False)

# ---------- Core stages ----------
def stage_recon(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    logger.log("Recon stage started", "INFO")
    recon_dir = run_dir / "recon"
    recon_dir.mkdir(exist_ok=True)
    targets = read_lines(TARGETS)
    if not targets:
        logger.log("No targets, skipping recon", "WARNING")
        return

    def per_target(target: str) -> Dict[str, Any]:
        tdir = recon_dir / target.replace(".", "_").replace("/", "_")
        tdir.mkdir(exist_ok=True)
        results: Dict[str, Any] = {"target": target, "status": "failed", "subdomains": [], "open_ports": [], "http_info": []}
        try:
            host = target
            if host.startswith("http://") or host.startswith("https://"):
                host = host.split("://", 1)[1].split("/", 1)[0]
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
            atomic_write(merged_subs, "\n".join(sorted(subs)))
            results["subdomains"] = sorted(subs)
            logger.log(f"{target}: {len(subs)} subdomains", "INFO")

            # Ports
            ports_out = tdir / "open_ports.txt"
            run_naabu(host, ports_out, cfg["limits"]["rps"], env)
            oports: List[Dict[str, Any]] = []
            if ports_out.exists():
                for line in ports_out.read_text(encoding="utf-8", errors="ignore").splitlines():
                    l = line.strip()
                    if l and ":" in l:
                        try:
                            h, port = l.rsplit(":", 1)
                            oports.append({"host": h, "port": int(port), "proto": "tcp"})
                        except Exception:
                            pass
            results["open_ports"] = oports
            logger.log(f"{target}: {len(oports)} open ports", "INFO")

            # HTTPX on subdomains (if any)
            httpx_in = tdir / "httpx_input.txt"
            httpx_out = tdir / "httpx_output.jsonl"
            if subs:
                atomic_write(httpx_in, "\n".join(sorted(subs)))
                run_httpx(httpx_in, httpx_out, env, cfg["limits"]["http_timeout"])
                if httpx_out.exists():
                    http_info: List[Dict[str, Any]] = []
                    for line in httpx_out.read_text(encoding="utf-8", errors="ignore").splitlines():
                        try:
                            http_info.append(json.loads(line))
                        except Exception:
                            pass
                    results["http_info"] = http_info

            results["status"] = "completed"
        except Exception as e:
            logger.log(f"Recon error {target}: {e}", "ERROR")
            results["status"] = "failed"
        return results

    with ThreadPoolExecutor(max_workers=cfg["limits"]["max_concurrent_scans"]) as ex:
        futs = {ex.submit(per_target, t): t for t in targets}
        for fut in as_completed(futs):
            res = fut.result()
            logger.log(f"Recon complete: {res.get('target')} -> {res.get('status')}", "INFO")

    logger.log("Recon stage complete", "SUCCESS")

def stage_vuln_scan(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    logger.log("Vuln scan stage started", "INFO")
    vuln_dir = run_dir / "vuln_scan"
    vuln_dir.mkdir(exist_ok=True)
    targets = read_lines(TARGETS)
    if not targets:
        logger.log("No targets, skipping vuln scan", "WARNING")
        return

    def per_target(target: str):
        tdir = vuln_dir / target.replace(".", "_").replace("/", "_")
        tdir.mkdir(exist_ok=True)
        try:
            nuclei_out = tdir / "nuclei_results.jsonl"
            run_nuclei_single_target(target if target.startswith("http") else f"http://{target}", nuclei_out, cfg, env)
            logger.log(f"Nuclei done for {target}", "INFO")
        except Exception as e:
            logger.log(f"Nuclei error {target}: {e}", "ERROR")

    with ThreadPoolExecutor(max_workers=cfg["limits"]["max_concurrent_scans"]) as ex:
        futs = [ex.submit(per_target, t) for t in targets]
        for _ in as_completed(futs):
            pass

    logger.log("Vuln scan stage complete", "SUCCESS")

def stage_report(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    logger.log("Reporting stage started", "INFO")
    report_dir = run_dir / "report"
    report_dir.mkdir(exist_ok=True)

    recon_results: Dict[str, Any] = {}
    vuln_results: Dict[str, Any] = {}

    recon_dir = run_dir / "recon"
    if recon_dir.exists():
        for td in recon_dir.iterdir():
            if not td.is_dir():
                continue
            tname = td.name
            subdomains = read_lines(td / "subdomains.txt")
            # open_ports normalized json from text
            ports: List[Dict[str, Any]] = []
            op = td / "open_ports.txt"
            if op.exists():
                for line in op.read_text(encoding="utf-8", errors="ignore").splitlines():
                    l = line.strip()
                    if l and ":" in l:
                        try:
                            h, port = l.rsplit(":", 1)
                            ports.append({"host": h, "port": int(port), "proto": "tcp"})
                        except Exception:
                            pass
            http_info = []
            httpx = td / "httpx_output.jsonl"
            if httpx.exists():
                for line in httpx.read_text(encoding="utf-8", errors="ignore").splitlines():
                    try:
                        http_info.append(json.loads(line))
                    except Exception:
                        pass
            recon_results[tname] = {"subdomains": subdomains, "open_ports": ports, "http_info": http_info}

    vuln_dir = run_dir / "vuln_scan"
    if vuln_dir.exists():
        for td in vuln_dir.iterdir():
            if not td.is_dir():
                continue
            tname = td.name
            nuclei_lines = []
            nuc = td / "nuclei_results.jsonl"
            if nuc.exists():
                nuclei_lines = nuc.read_text(encoding="utf-8", errors="ignore").splitlines()
            vuln_results[tname] = {"nuclei_raw": nuclei_lines}

    report_data = {
        "run_id": run_dir.name,
        "timestamp": datetime.now().isoformat(),
        "targets": read_lines(TARGETS),
        "recon_results": recon_results,
        "vuln_scan_results": vuln_results,
        "configuration": cfg
    }

    # JSON
    atomic_write(report_dir / "report.json", json.dumps(report_data, indent=2))

    # HTML (no ANSI, safe escaped)
    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def html_recon() -> str:
        chunks: List[str] = []
        for target, data in recon_results.items():
            subs = "".join(f"<li>{esc(x)}</li>" for x in data["subdomains"]) or "<li>None</li>"
            ports = "".join(f"<li>{esc(p['host'])}:{p['port']}/{p['proto']}</li>" for p in data["open_ports"]) or "<li>None</li>"
            http_sample = esc(json.dumps(data["http_info"][:100], indent=2))  # cap for readability
            chunks.append(f"""
            <div class="target-section">
              <h3>Target: {esc(target)}</h3>
              <h4>Subdomains</h4>
              <ul>{subs}</ul>
              <h4>Open Ports</h4>
              <ul>{ports}</ul>
              <h4>HTTPX (sample)</h4>
              <pre>{http_sample}</pre>
            </div>""")
        return "\n".join(chunks)

    def html_vuln() -> str:
        chunks: List[str] = []
        for target, data in vuln_results.items():
            raw = esc("\n".join(data.get("nuclei_raw", [])[:500]))
            chunks.append(f"""
            <div class="target-section">
              <h3>Target: {esc(target)}</h3>
              <h4>Nuclei Results (raw JSONL, first 500 lines)</h4>
              <pre>{raw or 'No results'}</pre>
            </div>""")
        return "\n".join(chunks)

    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Penetration Test Report - {esc(run_dir.name)}</title>
  <style>
    body {{ font-family: sans-serif; margin: 20px; background-color: #1e1e1e; color: #eee; }}
    h1, h2, h3 {{ color: #00aaff; }}
    pre {{ background-color: #2d2d2d; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    .section {{ margin-bottom: 30px; padding: 15px; border: 1px solid #00aaff; border-radius: 8px; }}
    .target-section {{ background-color: #282828; padding: 10px; margin-top: 10px; border-radius: 5px; }}
  </style>
</head>
<body>
  <h1>Penetration Test Report</h1>
  <p><strong>Run ID:</strong> {esc(run_dir.name)}</p>
  <p><strong>Timestamp:</strong> {esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>

  <div class="section">
    <h2>Targets</h2>
    <ul>{"".join(f"<li>{esc(t)}</li>" for t in report_data["targets"])}</ul>
  </div>

  <div class="section">
    <h2>Reconnaissance Results</h2>
    {html_recon()}
  </div>

  <div class="section">
    <h2>Vulnerability Scan Results</h2>
    {html_vuln()}
  </div>

  <div class="section">
    <h2>Configuration</h2>
    <pre>{esc(json.dumps(cfg, indent=2))}</pre>
  </div>
</body>
</html>
"""
    atomic_write(report_dir / "report.html", html)
    logger.log(f"Report written: {report_dir}", "SUCCESS")

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
    print("\n\033[96m" + "="*80 + "\033[0m")
    print("\033[96m" + "BL4CKC3LL_P4NTH30N - MAIN MENU".center(80) + "\033[0m")
    print("\033[96m" + "="*80 + "\033[0m")
    print("\033[95m1. Manage Targets\033[0m")
    print("\033[95m2. Refresh Sources + Merge Wordlists\033[0m")
    print("\033[95m3. Reconnaissance\033[0m")
    print("\033[95m4. Vulnerability Scan\033[0m")
    print("\033[95m5. Generate Report\033[0m")
    print("\033[95m6. Plugins\033[0m")
    print("\033[91m7. Exit\033[0m")
    print("\033[96m" + "="*80 + "\033[0m")

def get_choice() -> int:
    try:
        s = input("\n\033[93mSelect (1-7): \033[0m").strip()
        if s.isdigit():
            n = int(s)
            if 1 <= n <= 7:
                return n
    except (EOFError, KeyboardInterrupt):
        return 7
    except Exception:
        pass
    return 7

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
    print(f"\033[96m{APP} v{VERSION}\033[0m by {AUTHOR}")
    
    # Validate dependencies and environment
    if not validate_dependencies():
        logger.log("Critical dependencies missing. Please run install.sh or install manually.", "ERROR")
        logger.log("Continuing with limited functionality...", "WARNING")
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
            run_report_for_latest()
        elif c == 6:
            plugins_menu()
        elif c == 7:
            logger.log("Goodbye!", "INFO")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.log("Interrupted by user", "INFO")
    except Exception as e:
        logger.log(f"Fatal error: {e}", "ERROR")
        sys.exit(1)