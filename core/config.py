"""
PentestBrowser - Configuration Management
Centralized configuration for all components.
"""

import os
import json
import shutil
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


# Base paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
CHROMIUM_DIR = PROJECT_ROOT / "ungoogled-chromium"
EXTENSION_DIR = PROJECT_ROOT / "extension"
PROFILE_DIR = PROJECT_ROOT / "profile"
SESSIONS_DIR = PROJECT_ROOT / "sessions"
LOGS_DIR = PROJECT_ROOT / "logs"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
WORDLISTS_DIR = PROJECT_ROOT / "wordlists"
CA_CERT_DIR = PROJECT_ROOT / "certs"
DATA_DIR = PROJECT_ROOT / "data"

# Persistence files
CUSTOM_TOOLS_FILE = DATA_DIR / "custom_tools.json"
CONFIG_FILE = DATA_DIR / "config.json"


def resolve_chromium_bin() -> Path:
    """Resolve Chromium executable without hardcoding an exact extracted version folder."""
    env_path = os.environ.get("GREYTAB_CHROME_BIN", "").strip()
    if env_path:
        return Path(env_path).expanduser().resolve()

    direct_candidates = [
        PROJECT_ROOT / "chrome",
        PROJECT_ROOT / "chromium",
        PROJECT_ROOT / "ungoogled-chromium" / "chrome",
        PROJECT_ROOT / "ungoogled-chromium" / "chromium",
    ]
    for candidate in direct_candidates:
        if candidate.exists():
            return candidate.resolve()

    # Match extracted folders like ungoogled-chromium-<version>-<platform>/
    for folder in sorted(PROJECT_ROOT.glob("ungoogled-chromium*")):
        if not folder.is_dir():
            continue
        for exe in ("chrome", "chromium", "chrome-wrapper"):
            candidate = folder / exe
            if candidate.exists():
                return candidate.resolve()

    system_bin = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    if system_bin:
        return Path(system_bin).resolve()

    # Fallback to historical in-repo path for compatibility.
    return (PROJECT_ROOT / "ungoogled-chromium-145.0.7632.75-1-x86_64_linux" / "chrome").resolve()


CHROMIUM_BIN = resolve_chromium_bin()


@dataclass
class ProxyConfig:
    """Proxy (mitmproxy) configuration."""
    host: str = "127.0.0.1"
    port: int = 8080
    intercept_enabled: bool = True
    log_traffic: bool = True
    # Domains to exclude from interception
    exclude_domains: List[str] = field(default_factory=lambda: [
        "*.google.com",
        "*.googleapis.com",
        "*.gstatic.com",
        "accounts.google.com",
    ])


@dataclass
class APIConfig:
    """Backend API configuration."""
    host: str = "127.0.0.1"
    port: int = 8443
    cors_origins: List[str] = field(default_factory=lambda: [
        "chrome-extension://*",
        "http://127.0.0.1:*",
    ])


@dataclass
class ToolDefinition:
    """Definition of an external pentesting tool."""
    name: str
    command: str
    description: str
    category: str
    args_template: str = ""
    # Whether the tool needs a target URL
    requires_target: bool = True
    # Whether to stream output in real-time
    stream_output: bool = True


# Built-in tool definitions
BUILTIN_TOOLS: Dict[str, ToolDefinition] = {
    "ffuf": ToolDefinition(
        name="ffuf",
        command="ffuf",
        description="Fast web fuzzer for directory/file discovery, parameter fuzzing, and more",
        category="fuzzing",
        args_template="-u {target}/FUZZ -w {wordlist}",
        requires_target=True,
    ),
    "sqlmap": ToolDefinition(
        name="sqlmap",
        command="sqlmap",
        description="Automatic SQL injection detection and exploitation tool",
        category="injection",
        args_template="-u {target} --batch --level=3 --risk=2",
        requires_target=True,
    ),
    "xsser": ToolDefinition(
        name="xsser",
        command="xsser",
        description="Cross-site scripting (XSS) vulnerability scanner",
        category="xss",
        args_template="-u {target} --auto",
        requires_target=True,
    ),
    "nuclei": ToolDefinition(
        name="nuclei",
        command="nuclei",
        description="Fast vulnerability scanner based on templates",
        category="scanning",
        args_template="-u {target} -as",
        requires_target=True,
    ),
    "nikto": ToolDefinition(
        name="nikto",
        command="nikto",
        description="Web server vulnerability scanner",
        category="scanning",
        args_template="-h {target}",
        requires_target=True,
    ),
    "whatweb": ToolDefinition(
        name="whatweb",
        command="whatweb",
        description="Web technology fingerprinting",
        category="recon",
        args_template="{target}",
        requires_target=True,
    ),
    "wfuzz": ToolDefinition(
        name="wfuzz",
        command="wfuzz",
        description="Web application fuzzer",
        category="fuzzing",
        args_template="-w {wordlist} --hc 404 {target}/FUZZ",
        requires_target=True,
    ),
    "gobuster": ToolDefinition(
        name="gobuster",
        command="gobuster",
        description="Directory/file & DNS busting tool",
        category="fuzzing",
        args_template="dir -u {target} -w {wordlist}",
        requires_target=True,
    ),
    "httpx": ToolDefinition(
        name="httpx",
        command="httpx",
        description="Fast HTTP toolkit for probing",
        category="recon",
        args_template="-u {target} -sc -title -tech-detect",
        requires_target=True,
    ),
    "curl": ToolDefinition(
        name="curl",
        command="curl",
        description="Transfer data with URLs",
        category="utility",
        args_template="-v {target}",
        requires_target=True,
    ),
    "nmap": ToolDefinition(
        name="nmap",
        command="nmap",
        description="Network port scanner and service detection",
        category="scanning",
        args_template="-sV -sC {target}",
        requires_target=True,
    ),
    "hydra": ToolDefinition(
        name="hydra",
        command="hydra",
        description="Brute-force login cracker for network services",
        category="brute-force",
        args_template="-l admin -P {wordlist} {target} http-post-form",
        requires_target=True,
    ),
    "smbmap": ToolDefinition(
        name="smbmap",
        command="smbmap",
        description="SMB share enumeration and access checker",
        category="recon",
        args_template="-H {target}",
        requires_target=True,
    ),
    "enum4linux": ToolDefinition(
        name="enum4linux",
        command="enum4linux",
        description="Windows/Samba enumeration tool",
        category="recon",
        args_template="-a {target}",
        requires_target=True,
    ),
    "dirb": ToolDefinition(
        name="dirb",
        command="dirb",
        description="URL bruteforcer for web content scanning",
        category="fuzzing",
        args_template="{target} {wordlist}",
        requires_target=True,
    ),
    "wpscan": ToolDefinition(
        name="wpscan",
        command="wpscan",
        description="WordPress security scanner",
        category="scanning",
        args_template="--url {target} --enumerate vp,vt,u",
        requires_target=True,
    ),
    "commix": ToolDefinition(
        name="commix",
        command="commix",
        description="Command injection exploitation tool",
        category="injection",
        args_template="--url={target} --batch",
        requires_target=True,
    ),
    "sslyze": ToolDefinition(
        name="sslyze",
        command="sslyze",
        description="SSL/TLS configuration and certificate analyzer",
        category="scanning",
        args_template="{target}",
        requires_target=True,
    ),
}


@dataclass
class BrowserConfig:
    """Overall browser configuration."""
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    api: APIConfig = field(default_factory=APIConfig)
    tools: Dict[str, ToolDefinition] = field(default_factory=lambda: BUILTIN_TOOLS.copy())
    
    # Chromium launch flags
    chromium_flags: List[str] = field(default_factory=lambda: [
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-translate",
        "--metrics-recording-only",
        "--no-experiments",
        "--safebrowsing-disable-auto-update",
        # Proxy will be injected dynamically
    ])


def ensure_dirs():
    """Create all required directories."""
    for d in [PROFILE_DIR, SESSIONS_DIR, LOGS_DIR, SCRIPTS_DIR, WORDLISTS_DIR, CA_CERT_DIR, DATA_DIR]:
        d.mkdir(parents=True, exist_ok=True)


# ── Custom Tools Persistence ──────────────────────────────────────

def load_custom_tools() -> Dict[str, ToolDefinition]:
    """Load user-defined custom tools from persistent storage."""
    if not CUSTOM_TOOLS_FILE.exists():
        return {}
    try:
        with open(CUSTOM_TOOLS_FILE, 'r') as f:
            data = json.load(f)
        tools = {}
        for name, td in data.items():
            tools[name] = ToolDefinition(**td)
        return tools
    except Exception as e:
        print(f"[Config] Error loading custom tools: {e}")
        return {}


def save_custom_tools(tools: Dict[str, ToolDefinition]):
    """Save user-defined custom tools to persistent storage."""
    ensure_dirs()
    data = {}
    for name, td in tools.items():
        data[name] = asdict(td)
    try:
        with open(CUSTOM_TOOLS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[Config] Error saving custom tools: {e}")


# ── User Config Persistence ───────────────────────────────────────

def load_user_config() -> dict:
    """Load user config overrides (proxy port, etc)."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def save_user_config(config: dict):
    """Save user config overrides."""
    ensure_dirs()
    # Merge with existing
    existing = load_user_config()
    existing.update(config)
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(existing, f, indent=2)
    except Exception as e:
        print(f"[Config] Error saving config: {e}")


def get_config() -> BrowserConfig:
    """Get the current configuration, merging defaults with persisted overrides."""
    ensure_dirs()
    cfg = BrowserConfig()

    # Apply persisted user config
    user_cfg = load_user_config()
    if 'proxy_port' in user_cfg:
        cfg.proxy.port = int(user_cfg['proxy_port'])

    return cfg
