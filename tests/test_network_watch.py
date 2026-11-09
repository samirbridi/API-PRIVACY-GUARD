"""Read-only network watch unit tests using synthetic PIDs and endpoints."""
import json
import sys

import pytest

from api_privacy_guard.config import GuardError
from api_privacy_guard.network_watch import watch_connections, MAX_ALERTS
from api_privacy_guard.network_policy import validate_policy


class Missing(Exception):
    pass


class Denied(Exception):
    pass


class Zombie(Exception):
    pass


class Proc:
    def __init__(self):
        self.created = 100.0
        self.missing = False

    def create_time(self):
        if self.missing:
            raise Missing()
        return self.created


class API:
    NoSuchProcess = Missing
    AccessDenied = Denied
    ZombieProcess = Zombie

    def __init__(self):
        self.proc = Proc()

    def Process(self, pid):
        assert pid == 123
        return self.proc


def conn(ip, pid=123, name="agent.exe", port=443):
    return {"pid": pid, "process": name, "protocol": "tcp",
            "remote_ip": ip, "remote_port": port,
            "remote_scope": "global", "state": "ESTABLISHED"}


def snapshot(items=(), incomplete=False):
    return {"mode": "observe_only", "root_pid": 123,
            "connections": list(items), "inspected_processes": 2,
            "connections_observed": len(items), "incomplete": incomplete,
            "limitations": ["children_unavailable"] if incomplete else []}


class Collect:
    def __init__(self, entries):
        self.entries = entries
        self.calls = []

    def __call__(self, pid, **kwargs):
        self.calls.append(kwargs)
        return self.entries[len(self.calls) - 1]


def run(entries, **kwargs):
    return watch_connections(123, samples=len(entries), process_api=API(),
                             collect=Collect(entries), sleeper=lambda _: None,
                             **kwargs)


def test_deduplicate_across_samples_and_default_redaction():
    x = conn("8.8.8.8")
    y = conn("1.1.1.1", pid=234, name="child.exe", port=8443)
    out = run([snapshot([x]), snapshot([x, y]), snapshot([y])])
    assert out["samples_completed"] == 3
    assert out["unique_endpoints_observed"] == 2
    assert [v["first_seen_sample"] for v in out["alerts"]] == [1, 2]
    assert out["samples"][2]["new_unique_observations"]["review"] == 0
    assert out["incomplete"] is False
    assert "8.8.8.8" not in json.dumps(out)
    assert "1.1.1.1" not in json.dumps(out)
    assert out["traffic_blocked"] is False


def test_show_ip_is_explicit():
    out = run([snapshot([conn("8.8.8.8")])], show_ip=True)
    assert out["alerts"][0]["remote_ip"] == "8.8.8.8"


def test_simulated_policy_classification():
    policy = validate_policy({
        "schema_version": 1, "default_action": "review",
        "rules": [{"id": "allowed443", "action": "allow_candidate",
                   "process_names": ["agent.exe"], "protocols": ["tcp"],
                   "remote_ports": [443], "remote_scopes": ["global"],
                   "remote_cidrs": []}]})
    out = run([snapshot([conn("8.8.8.8"), conn("1.1.1.1", port=8443)])],
              policy=policy)
    assert out["unique_candidate_actions"]["allow_candidate"] == 1
    assert out["unique_candidate_actions"]["review"] == 1
    assert len(out["alerts"]) == 1


def test_root_reuse_stops_before_second_sample():
    ps = API()
    collect = Collect([snapshot([conn("8.8.8.8")])])
    def sleep(_):
        ps.proc.created = 200.0
    out = watch_connections(123, samples=2, process_api=ps,
                            collect=collect, sleeper=sleep)
    assert out["samples_completed"] == 1
    assert "root_pid_reused" in out["limitations"]
    assert len(collect.calls) == 1


def test_root_exit_stops_with_partial_result():
    ps = API()
    collect = Collect([snapshot([])])
    def sleep(_):
        ps.proc.missing = True
    out = watch_connections(123, samples=2, process_api=ps,
                            collect=collect, sleeper=sleep)
    assert out["incomplete"] and "root_process_unavailable" in out["limitations"]


def test_snapshot_failure_is_not_clean():
    def collector(pid, **kwargs):
        raise GuardError("sample failed")
    out = watch_connections(123, samples=1, process_api=API(),
                            collect=collector, sleeper=lambda _: None)
    assert out["incomplete"] is True
    assert out["samples_completed"] == 0
    assert "snapshot_unavailable" in out["limitations"]


def test_incomplete_children_and_excluded_children_reported():
    out = run([snapshot([], incomplete=True)], include_children=False)
    assert "children_unavailable" in out["limitations"]
    assert "children_excluded_by_operator" in out["limitations"]


def test_zero_observed_not_a_privacy_guarantee():
    out = run([snapshot([])])
    assert "does NOT prove" in out["warning"]


@pytest.mark.parametrize("samples, interval", [
    (0, 1), (31, 1), (True, 1), (1.1, 1),
    (1, float("nan")), (1, float("inf")), (1, 0.1),
    (1, 61), (1, True),
])
def test_invalid_sample_bounds(samples, interval):
    with pytest.raises(GuardError):
        watch_connections(123, samples=samples, interval=interval,
                          process_api=API())


def test_collect_passes_root_starttime_to_snapshot():
    c = Collect([snapshot([])])
    watch_connections(123, samples=1, process_api=API(), collect=c)
    assert c.calls[0]["expected_root_create_time"] == 100.0
    assert c.calls[0]["reveal_addresses"] is True


def test_new_snapshot_identity_guard_is_fail_closed():
    from api_privacy_guard.network_guard import take_snapshot
    class Fake:
        pid = 123
        def create_time(self): return 100.0
        def name(self): return "agent.exe"
        def net_connections(self, kind): return []
    class ProcessAPI(API):
        def Process(self, pid): return Fake()
    with pytest.raises(GuardError, match="identidade"):
        take_snapshot(123, process_api=ProcessAPI(), expected_root_create_time=101.0)


def test_alert_limit_and_no_ip_leak():
    rows = [conn(f"10.0.{i // 250}.{i % 250}") for i in range(MAX_ALERTS + 2)]
    out = run([snapshot(rows)])
    assert len(out["alerts"]) == MAX_ALERTS
    assert out["alerts_truncated"] is True
    assert "alert_display_limit" in out["limitations"]
    assert "10.0.0.0" not in json.dumps(out)


def test_cli_dispatches_read_only_watch(monkeypatch, capsys):
    from api_privacy_guard import cli
    import api_privacy_guard.network_watch as network_watch
    monkeypatch.setattr(network_watch, "watch_connections",
                        lambda pid, **kwargs: {"pid": pid, "active": False,
                                                "show_ip": kwargs["show_ip"]})
    monkeypatch.setattr(sys, "argv", ["apg", "network-watch", "--pid", "123"])
    cli.main()
    result = json.loads(capsys.readouterr().out)
    assert result == {"pid": 123, "active": False, "show_ip": False}
