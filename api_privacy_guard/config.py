"""Local profile configuration; never store credentials in this file."""
from __future__ import annotations
import json
import os
import re
from pathlib import Path

class GuardError(Exception):
    """A safe, non-secret error that may be returned to an AI tool."""


def config_path() -> Path:
    override = os.environ.get("API_PRIVACY_GUARD_CONFIG")
    if override:
        return Path(override).expanduser().resolve()
    base = os.getenv("LOCALAPPDATA") if os.name == "nt" else os.getenv("XDG_CONFIG_HOME")
    return Path(base).expanduser() / "APIPrivacyGuard" / "config.json" if base else Path.home() / ".config" / "APIPrivacyGuard" / "config.json"


EXAMPLE = {
    "schema_version": 1,
    "ssh_targets": {
        "demo-debian": {
            "enabled": False,
            "host": "example.invalid",
            "user": "deploy",
            "port": 22,
            "root": "/srv/my-project",
            "read": True,
            "write": False,
            "tasks": {
                "status": ["git", "-C", "/srv/my-project", "status", "--short"],
                "service_status": ["systemctl", "--user", "status", "my-app.service", "--no-pager"]
            }
        }
    },
    "api_services": {
        "demo-api": {
            "enabled": False,
            "base_url": "https://api.example.invalid/v1",
            "token_name": "demo-token",
            "auth": "bearer",
            "methods": ["GET"],
            "allowed_paths": ["/status"]
        }
    },
    "limits": {"max_file_bytes": 65536, "max_api_response_bytes": 65536}
}


def initialize(path: Path | None = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise GuardError("Configuração já existe; não sobrescrita.")
    with path.open("x", encoding="utf-8") as fp:
        json.dump(EXAMPLE, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    if os.name != "nt":
        path.chmod(0o600)
    return path


def load(path: Path | None = None) -> dict:
    path = path or config_path()
    try:
        with path.open("r", encoding="utf-8") as fp:
            cfg = json.load(fp)
    except FileNotFoundError:
        raise GuardError("Configuração não encontrada. Execute 'api-privacy-guard init'.") from None
    except (ValueError, OSError):
        raise GuardError("Não foi possível ler a configuração JSON.") from None
    if not isinstance(cfg, dict) or cfg.get("schema_version") != 1:
        raise GuardError("Versão de configuração incompatível.")
    if not isinstance(cfg.get("ssh_targets"), dict) or not isinstance(cfg.get("api_services"), dict):
        raise GuardError("Perfis de destino inválidos.")
    return cfg


def profile(cfg: dict, category: str, name: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
        raise GuardError("Nome de destino inválido.")
    p = cfg.get(category, {}).get(name)
    if not isinstance(p, dict) or p.get("enabled") is not True:
        raise GuardError("Destino não cadastrado ou não habilitado.")
    return p
