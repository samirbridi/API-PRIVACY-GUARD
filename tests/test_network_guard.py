"""Tests use a fake process API: never inspect real user processes."""
from __future__ import annotations

import json
import socket
from types import SimpleNamespace
import pytest

from api_privacy_guard.config import GuardError
from api_privacy_guard.network_guard import (
    _peer, destination_scope, take_snapshot,
)


class FakeNoSuchProcess(Exception):
    pass


class FakeAccessDenied(Exception):
    pass


class FakeZombieProcess(Exception):
    pass


class FakeProcess:
    def __init__(self, pid, name='agent', connections=(), children=(), deny=False):
        self.pid = pid
        self._name = name
        self._connections = connections
        self._children = children
        self.deny = deny

    def create_time(self):
        return 200.0

    def name(self):
        if self.deny:
            raise FakeAccessDenied()
        return self._name

    def children(self, recursive=False):
        assert recursive is True
        return self._children

    def net_connections(self, kind):
        assert kind == 'inet'
        return self._connections


def fake_api(root):
    return SimpleNamespace(
        NoSuchProcess=FakeNoSuchProcess,
        AccessDenied=FakeAccessDenied,
        ZombieProcess=FakeZombieProcess,
        Process=lambda pid: root,
    )


def peer(ip, port, status='ESTABLISHED', connection_type=socket.SOCK_STREAM):
    return SimpleNamespace(
        raddr=SimpleNamespace(ip=ip, port=port),
        status=status,
        type=connection_type,
    )


def test_snapshot_hides_ips_and_includes_process_children():
    child = FakeProcess(151, name='python', connections=[peer('198.51.100.23', 8443)])
    root = FakeProcess(150, name='IDE', connections=[peer('8.8.8.8', 443)], children=[child])
    out = take_snapshot(150, process_api=fake_api(root))
    assert out['mode'] == 'observe_only'
    assert out['inspected_processes'] == 2
    assert out['connections_observed'] == 2
    assert out['incomplete'] is False
    assert {x['pid'] for x in out['connections']} == {150, 151}
    assert all('remote_ip' not in x for x in out['connections'])
    assert '8.8.8.8' not in json.dumps(out)
    assert '198.51.100.23' not in json.dumps(out)


def test_snapshot_optin_addresses_and_no_children():
    child = FakeProcess(151, connections=[peer('192.0.2.1', 99)])
    root = FakeProcess(150, connections=[peer('127.0.0.1', 1234)], children=[child])
    out = take_snapshot(150, include_children=False, reveal_addresses=True, process_api=fake_api(root))
    assert out['connections_observed'] == 1
    assert out['connections'][0]['remote_ip'] == '127.0.0.1'
    assert out['connections'][0]['remote_scope'] == 'loopback'


def test_access_denied_not_reported_as_full_coverage():
    root = FakeProcess(150, children=[FakeProcess(151, deny=True)])
    out = take_snapshot(150, process_api=fake_api(root))
    assert out['incomplete'] is True
    assert 'process_unavailable' in out['limitations']


def test_root_unavailable_is_error():
    api = fake_api(FakeProcess(150))
    def missing(pid):
        raise FakeNoSuchProcess()
    api.Process = missing
    with pytest.raises(GuardError):
        take_snapshot(150, process_api=api)


@pytest.mark.parametrize('bad_pid', [0, -1, None, True, '21', 2**32])
def test_reject_invalid_pid(bad_pid):
    with pytest.raises(GuardError):
        take_snapshot(bad_pid, process_api=fake_api(FakeProcess(150)))


@pytest.mark.parametrize('ip,scope', [
    ('127.0.0.1', 'loopback'),
    ('::1', 'loopback'),
    ('169.254.1.2', 'link_local'),
    ('8.8.8.8', 'global'),
    ('192.168.1.10', 'private_or_reserved'),
    ('fe80::1%12', 'link_local'),
    ('not-an-ip', 'unknown'),
])
def test_scope(ip, scope):
    assert destination_scope(ip) == scope


def test_invalid_endpoint_ignored():
    root = FakeProcess(150, connections=[
        SimpleNamespace(raddr=(), status='NONE', type=socket.SOCK_DGRAM),
        peer('10.10.10.1', 65536),
    ])
    result = take_snapshot(150, process_api=fake_api(root))
    assert result['connections_observed'] == 0
    assert _peer(()) is None


def test_output_does_not_query_cmdline_environment_or_executable():
    root = FakeProcess(150, connections=[peer('1.1.1.1', 443)])
    result = take_snapshot(150, process_api=fake_api(root))
    assert 'cmdline' not in json.dumps(result)
    assert 'environment' not in json.dumps(result)
    assert 'exe' not in json.dumps(result)


def test_truncates_connections_and_marks_incomplete(monkeypatch):
    monkeypatch.setattr('api_privacy_guard.network_guard.MAX_CONNECTIONS', 2)
    root = FakeProcess(150, connections=[peer('8.8.8.8', 443) for _ in range(3)])
    result = take_snapshot(150, process_api=fake_api(root))
    assert result['connections_observed'] == 2
    assert result['incomplete'] is True
    assert 'connection_limit_reached' in result['limitations']


def test_snapshot_duplicate_child_pid_only_once():
    root = FakeProcess(150, connections=[peer('8.8.8.8', 443)])
    root._children = [root]
    result = take_snapshot(150, process_api=fake_api(root))
    assert result['connections_observed'] == 1
