"""AI environment detection.

Detects installed AI agent frameworks, local model servers, CLI tools,
MCP configurations, and AI-related packages on the user's desktop.
Read-only — no elevated privileges required.
"""

import json
import os
import platform
import re
import shutil
import subprocess


def scan_ai_environment() -> dict:
    """Detect AI tools, frameworks, and model servers."""
    system = platform.system()
    home = os.path.expanduser("~")

    results = {
        "claude": _detect_claude(system, home),
        "openai": _detect_openai(system, home),
        "agent_frameworks": _detect_agent_frameworks(),
        "openclaw": _detect_openclaw(home),
        "openbrain": _detect_openbrain(home),
        "ollama": _detect_ollama(system, home),
        "lm_studio": _detect_lm_studio(system, home),
        "mcp": _detect_mcp(system, home),
        "python_ai_packages": _detect_python_ai_packages(),
        "docker_ai_containers": _detect_docker_ai_containers(),
    }

    # Strip empty entries so the caller only sees what's present
    return {k: v for k, v in results.items() if v}


# ── Anthropic Claude ─────────────────────────────────────────────────

def _detect_claude(system: str, home: str) -> dict:
    """Detect Claude Desktop app, CLI, and MCP config."""
    info = {}

    # CLI
    version = _get_version(["claude", "--version"])
    if version:
        info["cli_version"] = version

    # Desktop app
    if system == "Darwin":
        app_path = "/Applications/Claude.app"
        if os.path.exists(app_path):
            info["desktop_app"] = True
    elif system == "Windows":
        local = os.environ.get("LOCALAPPDATA", "")
        if local and os.path.isdir(os.path.join(local, "Programs", "Claude")):
            info["desktop_app"] = True

    # Claude Code (VSCode extension or standalone)
    vscode_ext_dirs = []
    if system == "Windows":
        vscode_ext_dirs.append(os.path.join(home, ".vscode", "extensions"))
        vscode_ext_dirs.append(os.path.join(home, ".cursor", "extensions"))
    elif system == "Darwin":
        vscode_ext_dirs.append(os.path.join(home, ".vscode", "extensions"))
        vscode_ext_dirs.append(os.path.join(home, ".cursor", "extensions"))
    for ext_dir in vscode_ext_dirs:
        if os.path.isdir(ext_dir):
            try:
                for entry in os.listdir(ext_dir):
                    if "claude" in entry.lower() or "anthropic" in entry.lower():
                        info["claude_code_extension"] = entry
                        break
            except PermissionError:
                pass

    # Config directories
    claude_dir = os.path.join(home, ".claude")
    if os.path.isdir(claude_dir):
        info["config_dir"] = claude_dir

    if system == "Darwin":
        support_dir = os.path.join(
            home, "Library", "Application Support", "Claude",
        )
        if os.path.isdir(support_dir):
            info["app_support_dir"] = support_dir
            # Check for MCP server config inside Claude app support
            mcp_config = os.path.join(support_dir, "claude_desktop_config.json")
            servers = _read_mcp_config(mcp_config)
            if servers:
                info["mcp_servers"] = servers

    elif system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            support_dir = os.path.join(appdata, "Claude")
            if os.path.isdir(support_dir):
                info["app_support_dir"] = support_dir
                mcp_config = os.path.join(support_dir, "claude_desktop_config.json")
                servers = _read_mcp_config(mcp_config)
                if servers:
                    info["mcp_servers"] = servers

    return info


# ── OpenAI ───────────────────────────────────────────────────────────

def _detect_openai(system: str, home: str) -> dict:
    """Detect ChatGPT Desktop, openai CLI, and API key presence."""
    info = {}

    # CLI
    version = _get_version(["openai", "--version"])
    if version:
        info["cli_version"] = version

    # Desktop app
    if system == "Darwin":
        if os.path.exists("/Applications/ChatGPT.app"):
            info["desktop_app"] = True
    elif system == "Windows":
        local = os.environ.get("LOCALAPPDATA", "")
        if local and os.path.isdir(os.path.join(local, "Programs", "ChatGPT")):
            info["desktop_app"] = True

    # API key configured (presence only — never log the key)
    if os.environ.get("OPENAI_API_KEY"):
        info["api_key_set"] = True

    return info


# ── Agent Frameworks ─────────────────────────────────────────────────

def _detect_agent_frameworks() -> dict:
    """Detect AutoGPT, CrewAI, LangChain, LangGraph via pip and npm."""
    found = {}

    # Python packages
    pip_packages = {
        "autogpt": "autogpt",
        "crewai": "crewai",
        "langchain": "langchain",
        "langgraph": "langgraph",
    }
    pip_list = _get_pip_list()
    for key, pkg_name in pip_packages.items():
        version = pip_list.get(pkg_name)
        if version:
            found[key] = {"source": "pip", "version": version}

    # npm packages (global)
    npm_packages = {
        "autogpt": "autogpt",
        "langchain": "langchain",
    }
    npm_global = _get_npm_global_list()
    for key, pkg_name in npm_packages.items():
        version = npm_global.get(pkg_name)
        if version:
            entry = found.get(key, {})
            entry["npm_version"] = version
            if "source" not in entry:
                entry["source"] = "npm"
            found[key] = entry

    # CLI presence (autogpt ships its own CLI)
    for cli, label in [("autogpt", "autogpt"), ("crewai", "crewai")]:
        if shutil.which(cli) and label not in found:
            found[label] = {"source": "cli", "version": _get_version([cli, "--version"])}

    return found


# ── OpenClaw ─────────────────────────────────────────────────────────

def _detect_openclaw(home: str) -> dict:
    """Detect OpenClaw installation or config."""
    info = {}

    # CLI
    version = _get_version(["openclaw", "--version"])
    if version:
        info["cli_version"] = version
    elif shutil.which("openclaw"):
        info["cli"] = True

    # pip
    pip_list = _get_pip_list()
    if "openclaw" in pip_list:
        info["pip_version"] = pip_list["openclaw"]

    # Config directory
    config_dir = os.path.join(home, ".openclaw")
    if os.path.isdir(config_dir):
        info["config_dir"] = config_dir

    return info


# ── OpenBrain ────────────────────────────────────────────────────────

def _detect_openbrain(home: str) -> dict:
    """Detect OpenBrain installation or config."""
    info = {}

    # CLI
    version = _get_version(["openbrain", "--version"])
    if version:
        info["cli_version"] = version
    elif shutil.which("openbrain"):
        info["cli"] = True

    # pip
    pip_list = _get_pip_list()
    if "openbrain" in pip_list:
        info["pip_version"] = pip_list["openbrain"]

    # Config directory
    config_dir = os.path.join(home, ".openbrain")
    if os.path.isdir(config_dir):
        info["config_dir"] = config_dir

    return info


# ── Ollama ───────────────────────────────────────────────────────────

def _detect_ollama(system: str, home: str) -> dict:
    """Detect Ollama server, its version, and pulled models."""
    info = {}

    # CLI / version
    version = _get_version(["ollama", "--version"])
    if version:
        info["version"] = version

    # App presence
    if system == "Darwin" and os.path.exists("/Applications/Ollama.app"):
        info["desktop_app"] = True
    elif system == "Windows":
        local = os.environ.get("LOCALAPPDATA", "")
        if local and os.path.isdir(os.path.join(local, "Programs", "Ollama")):
            info["desktop_app"] = True

    # Check if running
    if shutil.which("ollama"):
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                info["running"] = True
                models = _parse_ollama_models(result.stdout)
                if models:
                    info["models"] = models
            else:
                info["running"] = False
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            info["running"] = False

    # Models directory
    if system == "Darwin":
        models_dir = os.path.join(home, ".ollama", "models")
    elif system == "Windows":
        models_dir = os.path.join(
            os.environ.get("USERPROFILE", home), ".ollama", "models",
        )
    else:
        models_dir = os.path.join(home, ".ollama", "models")

    if os.path.isdir(models_dir):
        info["models_dir"] = models_dir

    return info


def _parse_ollama_models(output: str) -> list[str]:
    """Parse 'ollama list' output into model names."""
    models = []
    for line in output.strip().splitlines()[1:]:  # skip header
        parts = line.split()
        if parts:
            models.append(parts[0])
    return models


# ── LM Studio ────────────────────────────────────────────────────────

def _detect_lm_studio(system: str, home: str) -> dict:
    """Detect LM Studio desktop application."""
    info = {}

    if system == "Darwin":
        if os.path.exists("/Applications/LM Studio.app"):
            info["desktop_app"] = True
        models_dir = os.path.join(home, ".cache", "lm-studio", "models")
        if os.path.isdir(models_dir):
            info["models_dir"] = models_dir
    elif system == "Windows":
        local = os.environ.get("LOCALAPPDATA", "")
        if local:
            if os.path.isdir(os.path.join(local, "Programs", "LM Studio")):
                info["desktop_app"] = True
            # Alternate common install location
            if os.path.isdir(os.path.join(local, "LM-Studio")):
                info["desktop_app"] = True
        userprofile = os.environ.get("USERPROFILE", home)
        models_dir = os.path.join(userprofile, ".cache", "lm-studio", "models")
        if os.path.isdir(models_dir):
            info["models_dir"] = models_dir

    # CLI (lms)
    version = _get_version(["lms", "--version"])
    if version:
        info["cli_version"] = version
    elif shutil.which("lms"):
        info["cli"] = True

    return info


# ── MCP (Model Context Protocol) ────────────────────────────────────

def _detect_mcp(system: str, home: str) -> dict:
    """Detect MCP server configurations across known locations."""
    info = {}
    configs_found = []

    # Claude Desktop MCP config (already checked in _detect_claude, but
    # gather all MCP configs across tools here too)
    if system == "Darwin":
        candidates = [
            os.path.join(home, "Library", "Application Support", "Claude",
                         "claude_desktop_config.json"),
            os.path.join(home, ".claude", "mcp.json"),
            os.path.join(home, ".config", "mcp", "config.json"),
        ]
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        candidates = [
            os.path.join(appdata, "Claude", "claude_desktop_config.json") if appdata else "",
            os.path.join(home, ".claude", "mcp.json"),
            os.path.join(home, ".config", "mcp", "config.json"),
        ]
    else:
        candidates = [
            os.path.join(home, ".claude", "mcp.json"),
            os.path.join(home, ".config", "mcp", "config.json"),
        ]

    for path in candidates:
        if path and os.path.isfile(path):
            servers = _read_mcp_config(path)
            if servers is not None:
                configs_found.append({
                    "path": path,
                    "servers": servers,
                })

    if configs_found:
        info["configs"] = configs_found

    # MCP CLI
    version = _get_version(["mcp", "--version"])
    if version:
        info["cli_version"] = version

    return info


def _read_mcp_config(path: str) -> list[str] | None:
    """Read an MCP config file and return server names, or None."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
        # Standard format: {"mcpServers": {"name": {...}}}
        servers = data.get("mcpServers", data.get("servers", {}))
        if isinstance(servers, dict) and servers:
            return list(servers.keys())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return None


# ── Python AI Packages ───────────────────────────────────────────────

def _detect_python_ai_packages() -> dict:
    """Detect AI-related Python packages via pip."""
    target_packages = [
        "anthropic",
        "openai",
        "langchain",
        "langchain-core",
        "langchain-community",
        "langgraph",
        "crewai",
        "autogen",
        "pyautogen",
        "transformers",
        "torch",
        "tensorflow",
        "huggingface-hub",
        "llama-index",
        "guidance",
        "dspy-ai",
        "vllm",
        "ctransformers",
        "llama-cpp-python",
        "chromadb",
        "pinecone-client",
        "weaviate-client",
    ]
    pip_list = _get_pip_list()
    found = {}
    for pkg in target_packages:
        version = pip_list.get(pkg)
        if version:
            found[pkg] = version
    return found


# ── Docker AI Containers ────────────────────────────────────────────

def _detect_docker_ai_containers() -> list[dict]:
    """Detect running Docker containers with AI-related images."""
    if not shutil.which("docker"):
        return []

    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return []
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []

    ai_keywords = [
        "ollama", "llama", "vllm", "tgi", "text-generation",
        "triton", "openai", "chatgpt", "langchain", "langserve",
        "crewai", "autogpt", "localai", "lmstudio", "oobabooga",
        "koboldai", "stable-diffusion", "comfyui", "automatic1111",
        "whisper", "mcp", "anthropic", "openclaw", "openbrain",
    ]

    containers = []
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, image, status = parts[0], parts[1], parts[2]
        image_lower = image.lower()
        name_lower = name.lower()
        if any(kw in image_lower or kw in name_lower for kw in ai_keywords):
            containers.append({
                "name": name,
                "image": image,
                "status": status,
            })

    return containers


# ── Shared Helpers ───────────────────────────────────────────────────

# Cache pip list so we only call it once per scan
_pip_cache: dict | None = None


def _get_pip_list() -> dict:
    """Return {package_name: version} from pip list. Cached."""
    global _pip_cache
    if _pip_cache is not None:
        return _pip_cache

    _pip_cache = {}
    pip_cmd = "pip3" if shutil.which("pip3") else "pip"
    if not shutil.which(pip_cmd):
        return _pip_cache

    try:
        result = subprocess.run(
            [pip_cmd, "list", "--format=json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            packages = json.loads(result.stdout)
            for pkg in packages:
                _pip_cache[pkg["name"].lower()] = pkg["version"]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError,
            json.JSONDecodeError, KeyError):
        pass

    return _pip_cache


_npm_cache: dict | None = None


def _get_npm_global_list() -> dict:
    """Return {package_name: version} from npm global list. Cached."""
    global _npm_cache
    if _npm_cache is not None:
        return _npm_cache

    _npm_cache = {}
    if not shutil.which("npm"):
        return _npm_cache

    try:
        result = subprocess.run(
            ["npm", "list", "-g", "--depth=0", "--json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            deps = data.get("dependencies", {})
            for pkg_name, pkg_info in deps.items():
                version = pkg_info.get("version", "")
                _npm_cache[pkg_name.lower()] = version
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError,
            json.JSONDecodeError, KeyError):
        pass

    return _npm_cache


def _get_version(cmd: list[str]) -> str | None:
    """Run a version command and extract the version string."""
    if not shutil.which(cmd[0]):
        return None

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=5,
        )
        output = (result.stdout + result.stderr).strip()
        if not output:
            return None

        version_match = re.search(r'(\d+\.\d+[\.\d]*)', output)
        if version_match:
            return version_match.group(1)

        return output.splitlines()[0][:50]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
