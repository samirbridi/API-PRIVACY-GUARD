"""Offline review of operator-entered WFP lab observations.

Never performs WFP/network operations; a consistent report is NOT proof.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .config import GuardError

MAX_BYTES = 16384
_ID = re.compile(r"APG_FILTER_ID=([1-9][0-9]{0,19})\Z")
_ERROR = re.compile(r"APG_FILTER_QUERY_ERROR=[0-9]{1,10} \((?:open|close|lookup)\)\Z")
_CONTEXT = frozenset({"disposable_vm", "isolated_network", "owned_endpoint",
                      "target_executable_used", "recovery_ready", "same_filter_id_in_probe"})
_NORMAL = frozenset({"id_line", "probe_during", "probe_after", "session_closed",
                     "helper_exit_code", "before", "during", "after"})
_CRASH = frozenset({"id_line", "probe_during", "probe_after", "after"})
_CONN = frozenset({"reachable", "blocked", "inconclusive"})


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key, value in pairs:
        if key in data:
            raise GuardError("Chave duplicada na evidência.")
        data[key] = value
    return data


def load_evidence(path: str | Path) -> object:
    try:
        with Path(path).expanduser().open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise GuardError("Arquivo de evidências excede 16 KiB.")
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique)
    except GuardError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        raise GuardError("Evidências JSON indisponíveis ou inválidas.") from None


def _object(value: object, fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GuardError("Estrutura do relatório desconhecida ou incompleta.")
    return value


def _id(line: object) -> int:
    if not isinstance(line, str):
        raise GuardError("Identificador WFP inválido.")
    match = _ID.fullmatch(line)
    if not match or int(match.group(1)) > (1 << 64) - 1:
        raise GuardError("Linha ou valor de filtro WFP inválido.")
    return int(match.group(1))


def _probe(value: object) -> str:
    if value == "APG_FILTER_PRESENT=true":
        return "present"
    if value == "APG_FILTER_PRESENT=false":
        return "absent"
    if isinstance(value, str) and _ERROR.fullmatch(value):
        return "query_error"
    raise GuardError("Linha do probe WFP inválida.")


def _conn(value: object) -> str:
    if not isinstance(value, str) or value not in _CONN:
        raise GuardError("Resultado de conectividade inválido.")
    return value


def evaluate_evidence(data: object) -> dict[str, Any]:
    root = _object(data, frozenset({"schema_version", "source",
                                   "operator_checks", "normal_run", "crash_run"}))
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise GuardError("Versão de evidência inválida.")
    if root["source"] != "manual_windows_vm_lab":
        raise GuardError("Origem de evidência inválida.")

    ctx = _object(root["operator_checks"], _CONTEXT)
    normal = _object(root["normal_run"], _NORMAL)
    crash = None if root["crash_run"] is None else _object(root["crash_run"], _CRASH)
    issues: list[str] = []

    for field in sorted(_CONTEXT):
        if type(ctx[field]) is not bool:
            raise GuardError("Declaração de operador inválida.")
        if not ctx[field]:
            issues.append("operator_check_missing_" + field)

    first_id = _id(normal["id_line"])
    for field, expected in (("probe_during", "present"), ("probe_after", "absent")):
        status = _probe(normal[field])
        if status != expected:
            issues.append("normal_" + field + "_not_confirmed")

    if normal["session_closed"] not in ("APG_SESSION_CLOSED=true", None):
        raise GuardError("Fechamento de sessão WFP inválido.")
    if normal["session_closed"] is None:
        issues.append("normal_session_close_unconfirmed")
    if type(normal["helper_exit_code"]) is not int or not 0 <= normal["helper_exit_code"] <= 255:
        raise GuardError("Código de saída inválido.")
    if normal["helper_exit_code"] != 0:
        issues.append("normal_helper_exit_failure")

    for field, expected in (("before", "reachable"), ("during", "blocked"),
                            ("after", "reachable")):
        if _conn(normal[field]) != expected:
            issues.append("normal_connectivity_" + field + "_not_confirmed")

    normal_consistent = not issues
    crash_consistent: bool | None = None
    if crash is None:
        issues.append("abrupt_termination_not_tested")
    else:
        length_before = len(issues)
        if _id(crash["id_line"]) == first_id:
            issues.append("reused_filter_id")
        if _probe(crash["probe_during"]) != "present":
            issues.append("crash_filter_not_confirmed_present")
        if _probe(crash["probe_after"]) != "absent":
            issues.append("crash_filter_not_confirmed_removed")
        if _conn(crash["after"]) != "reachable":
            issues.append("crash_connectivity_not_restored")
        crash_consistent = len(issues) == length_before

    return {
        "mode": "offline_operator_evidence_review",
        "assessment": "reported_checks_consistent" if not issues else "incomplete_or_inconsistent",
        "normal_run_consistent": normal_consistent,
        "crash_run_consistent": crash_consistent,
        "issues": issues,
        "independently_verified": False,
        "ready_for_production": False,
        "firewall_modified": False,
        "warning": "Only operator-provided observations were checked; WFP filtering and data protection were NOT independently verified.",
    }
