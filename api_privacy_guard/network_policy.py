"""Read-only egress policy evaluator for *observed* process connections.

This module never applies firewall rules. A process name is not a security
identity; all decisions are advisory and cannot certify complete traffic coverage.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from .config import GuardError

_MAX_POLICY_BYTES = 65536
_MAX_RULES = 64
_MAX_ITEMS = 32
_RULE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_NAME = re.compile(r"^[^\x00-\x1f\\/]{1,100}$")
_ACTIONS = frozenset({"allow_candidate", "block_candidate", "review"})
_SCOPES = frozenset({"loopback", "link_local", "multicast", "unspecified", "global", "private_or_reserved", "special_use", "unknown"})
_PROTOCOLS = frozenset({"tcp", "udp"})
_RULE_FIELDS = frozenset({"id", "action", "process_names", "protocols", "remote_ports", "remote_scopes", "remote_cidrs"})


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise GuardError("Chave duplicada na política de rede.")
        result[name] = value
    return result


def _str_list(value: object, name: str, pattern: re.Pattern[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, list) or not (1 <= len(value) <= _MAX_ITEMS):
        raise GuardError(f"Campo '{name}' deve ser uma lista não vazia de até {_MAX_ITEMS} entradas.")
    if any(not isinstance(x, str) or not x or (pattern and not pattern.fullmatch(x)) for x in value):
        raise GuardError(f"Campo '{name}' contém valor inválido.")
    if len(set(value)) != len(value):
        raise GuardError(f"Campo '{name}' contém duplicatas.")
    return tuple(value)


def validate_policy(data: object) -> dict[str, Any]:
    """Validate a purposely narrow, exact-match **simulation** policy.

    Rules must specify process names, protocols, ports and remote CIDRs/scopes.
    There is no default allow and no wildcard rule. These are *not* WFP rules.
    """
    if not isinstance(data, dict) or set(data) != {"schema_version", "default_action", "rules"}:
        raise GuardError("Política de rede inválida ou com campos desconhecidos.")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise GuardError("Versão da política de rede inválida.")
    if data["default_action"] != "review":
        raise GuardError("A política de observação exige ação padrão 'review'.")
    raw_rules = data["rules"]
    if not isinstance(raw_rules, list) or len(raw_rules) > _MAX_RULES:
        raise GuardError("Quantidade de regras inválida.")
    valid: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rule in raw_rules:
        if not isinstance(rule, dict) or set(rule) != _RULE_FIELDS:
            raise GuardError("Regra de rede inválida ou incompleta.")
        ident = rule["id"]
        if not isinstance(ident, str) or not _RULE_ID.fullmatch(ident) or ident in seen:
            raise GuardError("Identificador de regra inválido ou duplicado.")
        seen.add(ident)
        action = rule["action"]
        if not isinstance(action, str) or action not in _ACTIONS:
            raise GuardError("Decisão simulada inválida.")
        names = _str_list(rule["process_names"], "process_names", _NAME)
        protocols = _str_list(rule["protocols"], "protocols")
        if any(p not in _PROTOCOLS for p in protocols):
            raise GuardError("Protocolo não suportado.")
        ports = rule["remote_ports"]
        if not isinstance(ports, list) or not 1 <= len(ports) <= _MAX_ITEMS or any(
            type(p) is not int or not 1 <= p <= 65535 for p in ports
        ) or len(set(ports)) != len(ports):
            raise GuardError("Lista de portas inválida.")
        scopes = rule["remote_scopes"]
        cidrs = rule["remote_cidrs"]
        if not isinstance(scopes, list) or len(scopes) > _MAX_ITEMS or any(
            type(s) is not str or s not in _SCOPES for s in scopes
        ) or len(set(scopes)) != len(scopes):
            raise GuardError("Lista de categorias de endereço inválida.")
        if not isinstance(cidrs, list) or len(cidrs) > _MAX_ITEMS or any(
            not isinstance(c, str) or len(c) > 64 for c in cidrs
        ) or len(set(cidrs)) != len(cidrs):
            raise GuardError("Lista CIDR inválida.")
        if not scopes and not cidrs:
            raise GuardError("Informe categoria ou rede CIDR para cada regra.")
        canonical_cidrs = []
        for c in cidrs:
            try:
                network = ipaddress.ip_network(c, strict=True)
            except ValueError:
                raise GuardError("CIDR inválido ou não canônico.") from None
            canonical_cidrs.append(network)
        valid.append({
            "id": ident,
            "action": action,
            "process_names": names,
            "protocols": protocols,
            "remote_ports": tuple(ports),
            "remote_scopes": tuple(scopes),
            "remote_cidrs": tuple(canonical_cidrs),
        })
    return {"schema_version": 1, "default_action": "review", "rules": valid}


def load_policy(path: str | Path) -> dict[str, Any]:
    """Load a small JSON policy from a local path. Never contact any service."""
    try:
        p = Path(path).expanduser()
        with p.open("rb") as file:
            raw = file.read(_MAX_POLICY_BYTES + 1)
        if len(raw) > _MAX_POLICY_BYTES:
            raise GuardError("Arquivo de política excede 64 KiB.")
        data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_no_duplicate_keys)
    except GuardError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        raise GuardError("Não foi possível ler a política de rede JSON.") from None
    return validate_policy(data)


def _match(rule: dict[str, Any], entry: dict[str, Any]) -> bool:
    if entry.get("process") not in rule["process_names"]:
        return False
    if entry.get("protocol") not in rule["protocols"]:
        return False
    if type(entry.get("remote_port")) is not int or entry["remote_port"] not in rule["remote_ports"]:
        return False
    if entry.get("remote_scope") in rule["remote_scopes"]:
        return True
    ip = entry.get("remote_ip")
    if not isinstance(ip, str):
        return False
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return any(addr in cidr for cidr in rule["remote_cidrs"])


def evaluate_snapshot(
    snapshot: dict[str, Any],
    policy: dict[str, Any],
    *,
    show_ip: bool = False,
) -> dict[str, Any]:
    """Annotate a trusted local snapshot, never altering firewall or networking.

    Policy is already validated by load_policy/validate_policy. CIDR matches
    require internally collected remote_ip. Output stays redacted by default.
    """
    if snapshot.get("mode") != "observe_only" or not isinstance(snapshot.get("connections"), list):
        raise GuardError("Inventário de rede incompatível com simulação.")
    summary = {"allow_candidate": 0, "block_candidate": 0, "review": 0}
    annotated = []
    for item in snapshot["connections"]:
        if not isinstance(item, dict):
            raise GuardError("Inventário de rede inválido.")
        matches = [r for r in policy["rules"] if _match(r, item)]
        # Block candidates override review, which overrides allow candidates.
        # Never let rule order silently override a more restrictive suggestion.
        precedence = {"block_candidate": 0, "review": 1, "allow_candidate": 2}
        selected = min(matches, key=lambda r: precedence[r["action"]]) if matches else None
        action = selected["action"] if selected is not None else "review"
        summary[action] += 1
        output = {
            "pid": item.get("pid"),
            "process": item.get("process"),
            "protocol": item.get("protocol"),
            "remote_port": item.get("remote_port"),
            "remote_scope": item.get("remote_scope"),
            "state": item.get("state"),
            "candidate_action": action,
            "matched_rule": selected["id"] if selected else None,
        }
        if show_ip and isinstance(item.get("remote_ip"), str):
            output["remote_ip"] = item["remote_ip"]
        annotated.append(output)
    return {
        "mode": "dry_run_only",
        "enforcement_active": False,
        "traffic_blocked": False,
        "confidence": "partial_snapshot_only",
        "rule_identity_warning": "Process names are not verified executable identities.",
        "root_pid": snapshot.get("root_pid"),
        "inspected_processes": snapshot.get("inspected_processes", 0),
        "incomplete": bool(snapshot.get("incomplete", False)),
        "limitations": snapshot.get("limitations", []),
        "addresses_revealed": show_ip,
        "counts": summary,
        "connections": annotated,
    }
