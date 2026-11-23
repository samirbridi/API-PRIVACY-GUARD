"""Finite read-only multi-sample process connection observation.

Never filters traffic or inspects packet contents. Short-lived connections,
delegated traffic, unrelated processes and privileged sockets may be missed.
"""
from __future__ import annotations

import math
import time
from typing import Any, Callable

from .config import GuardError
from .network_guard import _load_psutil, take_snapshot
from .network_policy import evaluate_snapshot, validate_policy

MAX_SAMPLES = 30
MAX_UNIQUE = 3000
MAX_ALERTS = 100


def watch_connections(
    root_pid: int, *, policy: dict[str, Any] | None = None,
    samples: int = 5, interval: float = 1.0,
    include_children: bool = True, show_ip: bool = False,
    process_api: Any | None = None,
    collect: Callable[..., dict[str, Any]] = take_snapshot,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Compare observed endpoints; only report candidates for review."""
    if type(root_pid) is not int or not 1 <= root_pid <= 2**32 - 1:
        raise GuardError("PID inválido.")
    if type(samples) is not int or not 1 <= samples <= MAX_SAMPLES:
        raise GuardError("Número de amostras inválido.")
    if type(interval) not in (int, float) or not math.isfinite(interval) or not 0.25 <= interval <= 60:
        raise GuardError("Intervalo inválido.")
    if type(show_ip) is not bool or type(include_children) is not bool:
        raise GuardError("Parâmetros de observação inválidos.")
    if policy is None:
        policy = validate_policy({"schema_version": 1, "default_action": "review", "rules": []})
    ps = process_api if process_api is not None else _load_psutil()
    errors = (ps.NoSuchProcess, ps.AccessDenied, ps.ZombieProcess)
    try:
        identity = ps.Process(root_pid).create_time()
    except errors:
        raise GuardError("Processo raiz não disponível.") from None

    seen = set()
    alerts = []
    limitations = set()
    if not include_children:
        limitations.add("children_excluded_by_operator")
    total = {"allow_candidate": 0, "block_candidate": 0, "review": 0}
    history = []
    truncated = False
    for number in range(1, samples + 1):
        if number > 1:
            sleeper(float(interval))
        try:
            if ps.Process(root_pid).create_time() != identity:
                limitations.add("root_pid_reused")
                break
        except errors:
            limitations.add("root_process_unavailable")
            break
        try:
            snapshot = collect(
                root_pid, include_children=include_children,
                reveal_addresses=True, process_api=ps,
                expected_root_create_time=identity,
            )
        except GuardError:
            limitations.add("snapshot_unavailable")
            break
        if snapshot.get("incomplete"):
            limitations.add("partial_process_scan")
        limitations.update(x for x in snapshot.get("limitations", [])
                           if isinstance(x, str) and len(x) <= 80)
        evaluated = evaluate_snapshot(snapshot, policy, show_ip=True)
        fresh = {"allow_candidate": 0, "block_candidate": 0, "review": 0}
        for entry in evaluated["connections"]:
            pid, ip, port = entry.get("pid"), entry.get("remote_ip"), entry.get("remote_port")
            if type(pid) is not int or type(port) is not int or not isinstance(ip, str):
                limitations.add("endpoint_identity_unavailable")
                continue
            key = (pid, entry.get("process"), entry.get("protocol"), ip, port)
            if key in seen:
                continue
            if len(seen) >= MAX_UNIQUE:
                truncated = True
                limitations.add("unique_endpoint_limit")
                continue
            seen.add(key)
            action = entry["candidate_action"]
            total[action] += 1
            fresh[action] += 1
            if action != "allow_candidate":
                if len(alerts) < MAX_ALERTS:
                    alert = {
                        "first_seen_sample": number, "pid": pid,
                        "process": entry.get("process"),
                        "protocol": entry.get("protocol"), "remote_port": port,
                        "remote_scope": entry.get("remote_scope"),
                        "candidate_action": action,
                        "matched_rule": entry.get("matched_rule"),
                    }
                    if show_ip:
                        alert["remote_ip"] = ip
                    alerts.append(alert)
                else:
                    limitations.add("alert_display_limit")
                    truncated = True
        history.append({
            "sample": number,
            "processes_inspected": snapshot.get("inspected_processes", 0),
            "connections_observed": snapshot.get("connections_observed", 0),
            "new_unique_observations": fresh,
            "incomplete": bool(snapshot.get("incomplete", False)),
        })
    if len(history) != samples:
        limitations.add("sampling_stopped_early")
    return {
        "mode": "read_only_network_watch",
        "enforcement_active": False, "traffic_blocked": False,
        "coverage": "finite_best_effort_samples",
        "root_pid": root_pid, "include_children": include_children,
        "addresses_revealed": show_ip,
        "samples_requested": samples, "samples_completed": len(history),
        "unique_endpoints_observed": len(seen),
        "unique_candidate_actions": total,
        "incomplete": bool(limitations),
        "limitations": sorted(limitations),
        "alerts_truncated": truncated,
        "alerts": alerts, "samples": history,
        "warning": (
            "Advisory only. Process names are not verified executable identities. "
            "Short-lived, delegated or out-of-tree traffic can be missed. "
            "Zero observed connections does NOT prove no data was sent."
        ),
    }
