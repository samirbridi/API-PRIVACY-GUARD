"""Local read-only process-network inventory for developer-controlled agent processes.

Observational only: sampling net_connections is NOT a firewall, egress
interception, packet capture, or evidence that no other traffic took place.
No packets or connection contents are collected, and IPs are hidden by default.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any

from .config import GuardError

MAX_PROCESSES = 256
MAX_CONNECTIONS = 3000


def _load_psutil():
    try:
        import psutil
    except ImportError:
        raise GuardError(
            'Monitoramento indisponível. Instale a dependência opcional: '
            'python -m pip install -e ".[network]"'
        ) from None
    return psutil


def destination_scope(ip: str) -> str:
    """IP classification only; no DNS lookups or endpoint reputational claims."""
    try:
        address = ipaddress.ip_address(ip.split('%', 1)[0])
    except ValueError:
        return 'unknown'
    if address.is_loopback:
        return 'loopback'
    if address.is_link_local:
        return 'link_local'
    if address.is_multicast:
        return 'multicast'
    if address.is_unspecified:
        return 'unspecified'
    if address.is_global:
        return 'global'
    if address.is_private:
        return 'private_or_reserved'
    return 'special_use'


def _peer(remote: Any) -> tuple[str, int] | None:
    """Understand psutil's tuple/namedtuple remote address formats."""
    if not remote:
        return None
    try:
        ip = str(remote.ip if hasattr(remote, 'ip') else remote[0])
        port = int(remote.port if hasattr(remote, 'port') else remote[1])
    except (AttributeError, TypeError, IndexError, ValueError):
        return None
    if not 0 <= port <= 65535:
        return None
    return ip, port


def take_snapshot(
    root_pid: int,
    *,
    include_children: bool = True,
    reveal_addresses: bool = False,
    process_api: Any | None = None,
    expected_root_create_time: float | None = None,
) -> dict[str, Any]:
    """Inspect a live root process and (by default) current child processes.

    Uses psutil.Process.net_connections rather than system-wide enumeration.
    Failed process inspection is surfaced as incomplete, never as clean traffic.
    """
    if type(root_pid) is not int or not 1 <= root_pid <= 2**32 - 1:
        raise GuardError('PID inválido.')
    ps = process_api if process_api is not None else _load_psutil()
    process_errors = (ps.NoSuchProcess, ps.AccessDenied, ps.ZombieProcess)
    try:
        root = ps.Process(root_pid)
        identity = root.create_time()
        if expected_root_create_time is not None and identity != expected_root_create_time:
            raise GuardError('Processo raiz alterou identidade durante a observação.')
    except process_errors:
        raise GuardError('Processo raiz indisponível ou sem permissão de leitura.') from None

    incomplete: list[str] = []
    processes = [root]
    if include_children:
        try:
            processes += root.children(recursive=True)
        except process_errors:
            incomplete.append('children_unavailable')
    if len(processes) > MAX_PROCESSES:
        processes = processes[:MAX_PROCESSES]
        incomplete.append('process_limit_reached')

    observations: list[dict[str, Any]] = []
    inspected = 0
    seen_pids: set[int] = set()
    limit_reached = False
    for process in processes:
        if len(observations) >= MAX_CONNECTIONS:
            limit_reached = True
            break
        try:
            pid = int(process.pid)
            if pid in seen_pids:
                continue
            seen_pids.add(pid)
            process.create_time()
            name = process.name()
            connections = process.net_connections(kind='inet')
            inspected += 1
        except process_errors:
            incomplete.append('process_unavailable')
            continue
        name = name if isinstance(name, str) else 'unknown'
        name = name[:100]
        for connection in connections:
            peer = _peer(connection.raddr)
            if peer is None:
                continue
            ip, port = peer
            try:
                kind = 'tcp' if connection.type == socket.SOCK_STREAM else (
                    'udp' if connection.type == socket.SOCK_DGRAM else 'other'
                )
                state = str(connection.status).upper()[:32]
                scope = destination_scope(ip)
            except (TypeError, ValueError, AttributeError):
                incomplete.append('connection_parse_error')
                continue
            entry = {
                'pid': pid,
                'process': name,
                'protocol': kind,
                'remote_port': port,
                'remote_scope': scope,
                'state': state,
            }
            if reveal_addresses:
                entry['remote_ip'] = ip
            observations.append(entry)
            if len(observations) >= MAX_CONNECTIONS:
                limit_reached = True
                break
    if limit_reached:
        incomplete.append('connection_limit_reached')

    observations.sort(
        key=lambda x: (
            x['pid'], x['protocol'], x['remote_port'], x['state'], x.get('remote_ip', '')
        )
    )
    return {
        'mode': 'observe_only',
        'coverage': 'best_effort_snapshot',
        'root_pid': root_pid,
        'include_children': include_children,
        'addresses_revealed': reveal_addresses,
        'inspected_processes': inspected,
        'connections_observed': len(observations),
        'incomplete': bool(incomplete),
        'limitations': sorted(set(incomplete)),
        'connections': observations,
    }
