"""Manual-only WFP lab command planner. No WFP writes or subprocess launches.

The Windows SDK helper is manually compiled and launched in a disposable VM.
Never expose this function as an MCP tool or auto-run it from an IDE.
"""
from __future__ import annotations

import ipaddress
import ntpath
import re
import sys
from typing import Any, Callable

from .config import GuardError
from .wfp_preflight import validate, validate_path, fingerprint


def prepare_lab_command(
    proposal: dict,
    helper_executable: str,
    *,
    seconds: int = 10,
    vm_acknowledged: bool = False,
    platform: str | None = None,
    inspect: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Prepare, but never execute, a strict single-rule Windows lab command."""
    if not vm_acknowledged:
        raise GuardError("Confirme explicitamente o uso em VM descartável.")
    if (sys.platform if platform is None else platform) != "win32":
        raise GuardError("O laboratório WFP exige Windows.")
    if type(seconds) is not int or not 5 <= seconds <= 30:
        raise GuardError("A duração deve ser de 5 a 30 segundos.")
    validate_path(helper_executable)
    if ntpath.basename(helper_executable).lower() != "wfp_lab_block.exe":
        raise GuardError("O executável auxiliar deve ser wfp_lab_block.exe.")
    rules = validate(proposal)
    if len(rules) != 1:
        raise GuardError("O laboratório exige exatamente uma regra.")
    rule = rules[0]
    addr = ipaddress.ip_address(rule["remote_ip"])
    if addr.version != 4 or rule["ip_version"] != 4:
        raise GuardError("Esta fase aceita somente IPv4.")
    examine = fingerprint if inspect is None else inspect
    target_info = examine(rule["executable"])
    helper_info = examine(helper_executable)
    for item in (target_info, helper_info):
        if (not isinstance(item, dict) or
            not isinstance(item.get("sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise GuardError("Fingerprint local inválido.")
    if target_info["sha256"] != rule["sha256"]:
        raise GuardError("Executável difere do SHA-256 autorizado.")
    command = [
        helper_executable,
        "--lab-block", "--exe", rule["executable"],
        "--sha256", rule["sha256"],
        "--ip", rule["remote_ip"], "--port", str(rule["remote_port"]),
        "--protocol", rule["protocol"], "--seconds", str(seconds),
        "--confirm", "LAB-ONLY-EPHEMERAL-BLOCK",
    ]
    return {
        "mode": "manual_lab_command_only",
        "requires_disposable_windows_vm": True,
        "helper_sha256": helper_info["sha256"],
        "approved_target_sha256": target_info["sha256"],
        "will_modify_firewall_if_manually_executed": True,
        "executed": False,
        "filters_installed": 0,
        "command_argv": command,
        "environment_required": {
            "APG_WFP_DISPOSABLE_VM": "I_ACCEPT_VM_ONLY_LAB",
        },
        "warning": (
            "Planner only. Native helper WILL block matching traffic when manually "
            "run in a disposable VM. No process or firewall operation was started."
        ),
    }
