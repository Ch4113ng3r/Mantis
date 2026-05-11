"""
MANTIS configuration management.

Loads config from ~/.mantis/config.yaml with environment variable
expansion and sensible defaults. Config is a plain dict accessible
throughout the application.
"""

import os
import yaml
import re
from pathlib import Path
from typing import Any, Optional

# Default config values used when config.yaml is missing or incomplete
DEFAULTS = {
    "llm": {
        "default_provider": "anthropic",
        "providers": {
            "anthropic": {
                "base_url": "https://api.anthropic.com",
                "models": {
                    "triage": "claude-haiku-4-5-20251001",
                    "scanner": "claude-sonnet-4-20250514",
                    "verifier": "claude-opus-4-20250514",
                    "exploiter": "claude-sonnet-4-20250514",
                },
            },
        },
    },
    "engagement": {
        "max_concurrent_agents": 5,
        "human_approval_required": True,
        "auto_checkpoint_interval": 30,
        "max_token_budget_usd": 50.0,
    },
    "network": {
        "docker_image": "mantis-kali",
        "nmap_args": "-sV -sC",
        "port_range": "1-10000",
        "timeout_seconds": 300,
    },
    "webapp": {
        "max_crawl_depth": 5,
        "max_urls": 500,
        "user_agent": "MANTIS/1.0 Security Scanner",
        "follow_redirects": True,
        "exclude_patterns": ["*/logout*", "*/static/*", "*/assets/*"],
    },
    "codereview": {
        "spot_check_ratio": 0.20,
        "recalibration_threshold": 5,
        "max_context_tokens": 800,
        "skip_patterns": [
            "*/test_*", "*/migrations/*", "*/__pycache__/*",
            "*/vendor/*", "*/node_modules/*",
        ],
    },
    "report": {
        "formats": ["markdown", "json", "html"],
        "include_evidence": True,
        "include_remediation": True,
        "cvss_version": "3.1",
    },
    "storage": {
        "db_path": "~/.mantis/mantis.db",
        "knowledge_graph": "~/.mantis/knowledge_graph.json",
        "mechanism_memory": "~/.mantis/mechanisms.jsonl",
        "results_dir": "~/.mantis/results",
    },
}


def _expand_env_vars(value: Any) -> Any:
    """Recursively expand ${ENV_VAR} references in config values."""
    if isinstance(value, str):
        # Replace ${VAR_NAME} with environment variable value
        pattern = re.compile(r"\$\{(\w+)\}")
        def replacer(match):
            var_name = match.group(1)
            return os.environ.get(var_name, match.group(0))
        return pattern.sub(replacer, value)
    elif isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_expand_env_vars(item) for item in value]
    return value


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base, returning new dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: Optional[str] = None) -> dict:
    """
    Load configuration from YAML file with env var expansion.

    Priority: explicit path > ~/.mantis/config.yaml > defaults.

    Args:
        config_path: Optional explicit path to config.yaml

    Returns:
        Merged configuration dict with all values resolved.
    """
    if config_path is None:
        config_path = os.path.expanduser("~/.mantis/config.yaml")

    config = DEFAULTS.copy()

    if os.path.exists(config_path):
        with open(config_path) as f:
            user_config = yaml.safe_load(f) or {}
        config = _deep_merge(config, user_config)

    # Expand environment variables
    config = _expand_env_vars(config)

    # Expand ~ in paths
    for key in ("db_path", "knowledge_graph", "mechanism_memory", "results_dir"):
        if key in config.get("storage", {}):
            config["storage"][key] = os.path.expanduser(config["storage"][key])

    return config


def get_api_key(config: dict, provider: Optional[str] = None) -> str:
    """Extract the API key for the given provider."""
    provider = provider or config["llm"]["default_provider"]
    provider_config = config["llm"]["providers"].get(provider, {})
    api_key = provider_config.get("api_key", "")

    # Fall back to environment variable
    if not api_key or api_key.startswith("${"):
        env_var = f"{provider.upper()}_API_KEY"
        api_key = os.environ.get(env_var, "")

    return api_key


def get_model(config: dict, role: str, provider: Optional[str] = None) -> str:
    """Get model string for a given role (triage, scanner, verifier, exploiter)."""
    provider = provider or config["llm"]["default_provider"]
    models = config["llm"]["providers"].get(provider, {}).get("models", {})
    return models.get(role, "claude-sonnet-4-20250514")


# OOB Callback defaults (added in v1.2)
DEFAULTS["oob"] = {
    "mode": "interactsh",            # interactsh, local, webhook
    "local_port": 8888,
    "external_url": "",              # Your public IP/domain for local mode
    "interactsh_server": "oast.fun",
    "wait_seconds": 10,              # How long to wait for callbacks
    "enabled": True,                 # Set to false to skip OOB tests
}
