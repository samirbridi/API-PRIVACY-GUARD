"""Minimal local metadata-only audit: never save prompts, responses or credentials."""
from __future__ import annotations
import hashlib
import json
import os
import time
from pathlib import Path
from .config import config_path


def record(operation: str, destination: str, result: str, resource: str = "") -> None:
    try:
        directory = config_path().parent
        directory.mkdir(parents=True, exist_ok=True)
        file = directory / "audit.jsonl"
        event = {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operation": operation,
            "destination": destination,
            "result": result,
        }
        if resource:
            event["resource_sha256_prefix"] = hashlib.sha256(resource.encode()).hexdigest()[:16]
        # No user-provided data, commands, results or secrets are logged.
        with file.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(event, ensure_ascii=False) + "\n")
        if os.name != "nt":
            file.chmod(0o600)
    except OSError:
        # Audit failure is handled by the calling layer where enabled.
        raise
