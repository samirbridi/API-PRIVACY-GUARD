"""All network policy tests use fake snapshots and temporary policies; no network/Windows changes."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from api_privacy_guard.config import GuardError
from api_privacy_guard.network_policy import validate_policy, load_policy, evaluate_snapshot


RULE = {
    "id": "sample-ssh",
    "action": "allow_candidate",
    "process_names": ["ssh.exe"],
    "protocols": ["tcp"],
    "remote_ports": [22],
    "remote_scopes": ["private_or_reserved"],
    "remote_cidrs": [],
}
POLICY = {"schema_version": 1, "default_action": "review", "rules": [RULE]}


def fake_connection(**overrides):
    entry = {"pid": 7, "process": "ssh.exe", "protocol": "tcp",
             "remote_port": 22, "remote_scope": "private_or_reserved",
             "remote_ip": "192.168.1.25", "state": "ESTABLISHED"}
    entry.update(overrides)
    return entry


def snapshot(*entries, incomplete=False):
    return {"mode": "observe_only", "root_pid": 7, "inspected_processes": 1,
            "incomplete": incomplete, "limitations": ["process_unavailable"] if incomplete else [],
            "connections": list(entries)}


def test_default_review_and_allow_candidate():
    policy = validate_policy(copy.deepcopy(POLICY))
    out = evaluate_snapshot(snapshot(fake_connection(), fake_connection(process="evil.exe")), policy)
    assert out["mode"] == "dry_run_only"
    assert out["traffic_blocked"] is False
    assert out["enforcement_active"] is False
    assert out["counts"] == {"allow_candidate": 1, "review": 1, "block_candidate": 0}
    assert out["connections"][0]["matched_rule"] == "sample-ssh"


def test_private_ip_redacted_unless_explicit():
    p = validate_policy(copy.deepcopy(POLICY))
    out = evaluate_snapshot(snapshot(fake_connection()), p)
    assert "192.168.1.25" not in json.dumps(out)
    assert "remote_ip" not in out["connections"][0]
    shown = evaluate_snapshot(snapshot(fake_connection()), p, show_ip=True)
    assert shown["connections"][0]["remote_ip"] == "192.168.1.25"


def test_cidr_rule_matches_ipv4_and_ipv6():
    p = copy.deepcopy(POLICY)
    p["rules"][0]["remote_scopes"] = []
    p["rules"][0]["remote_cidrs"] = ["10.0.0.0/8", "2001:db8::/32"]
    pol = validate_policy(p)
    snaps = snapshot(fake_connection(remote_ip="10.7.8.9",remote_scope="private_or_reserved"),
                     fake_connection(remote_ip="2001:db8::1",remote_scope="private_or_reserved"),
                     fake_connection(remote_ip="192.168.0.1"))
    out = evaluate_snapshot(snaps, pol)
    assert [x["candidate_action"] for x in out["connections"]] == ["allow_candidate", "allow_candidate", "review"]


def test_missing_or_invalid_remote_ip_never_matches_cidr():
    p = copy.deepcopy(POLICY)
    p["rules"][0]["remote_scopes"] = []
    p["rules"][0]["remote_cidrs"] = ["10.0.0.0/8"]
    pol = validate_policy(p)
    for entry in (fake_connection(remote_ip="bad_ip"), fake_connection(remote_ip=None)):
        assert evaluate_snapshot(snapshot(entry), pol)["counts"]["review"] == 1


def test_protocol_port_process_must_all_match():
    p = validate_policy(copy.deepcopy(POLICY))
    entries = [fake_connection(protocol="udp"), fake_connection(remote_port=443), fake_connection(process="SSH.EXE"), fake_connection(remote_port=True)]
    out = evaluate_snapshot(snapshot(*entries), p)
    assert out["counts"]["review"] == 4


def test_block_candidate_overrides_allow_independent_of_rule_order():
    p = copy.deepcopy(POLICY)
    block = copy.deepcopy(RULE)
    block.update(id="block-private", action="block_candidate")
    p["rules"] = [p["rules"][0], block]
    out = evaluate_snapshot(snapshot(fake_connection()), validate_policy(p))
    assert out["connections"][0]["candidate_action"] == "block_candidate"
    assert out["connections"][0]["matched_rule"] == "block-private"


def test_incomplete_snapshot_is_not_claimed_as_covered():
    p = validate_policy(copy.deepcopy(POLICY))
    out = evaluate_snapshot(snapshot(incomplete=True), p)
    assert out["incomplete"] is True
    assert "process_unavailable" in out["limitations"]
    assert out["confidence"] == "partial_snapshot_only"


def test_empty_snapshot_never_proves_no_leakage():
    p = validate_policy(copy.deepcopy(POLICY))
    out = evaluate_snapshot(snapshot(), p)
    assert out["counts"] == {"allow_candidate": 0, "block_candidate": 0, "review": 0}
    assert out["confidence"] == "partial_snapshot_only"


@pytest.mark.parametrize("mutate", [
    lambda p: p.update(default_action="allow"),
    lambda p: p.update(schema_version=True),
    lambda p: p.update(extra="skip"),
    lambda p: p["rules"][0].update(extra="skip"),
    lambda p: p["rules"][0].update(id="../bad"),
    lambda p: p["rules"][0].update(action="permit"),
    lambda p: p["rules"][0].update(process_names=["ssh.exe", "ssh.exe"]),
    lambda p: p["rules"][0].update(process_names=["../ssh.exe"]),
    lambda p: p["rules"][0].update(protocols=["icmp"]),
    lambda p: p["rules"][0].update(remote_ports=[0]),
    lambda p: p["rules"][0].update(remote_ports=[True]),
    lambda p: p["rules"][0].update(remote_ports=[22, 22]),
    lambda p: p["rules"][0].update(remote_scopes=["internet"]),
    lambda p: p["rules"][0].update(remote_scopes=[], remote_cidrs=[]),
    lambda p: p["rules"][0].update(remote_cidrs=["10.0.0.1/8"]),
    lambda p: p["rules"][0].update(remote_cidrs=["not-a-cidr"]),
])
def test_reject_invalid_policy(mutate):
    p = copy.deepcopy(POLICY)
    mutate(p)
    with pytest.raises(GuardError):
        validate_policy(p)


def test_reject_duplicate_rule_ids():
    p = copy.deepcopy(POLICY)
    p["rules"].append(copy.deepcopy(RULE))
    with pytest.raises(GuardError):
        validate_policy(p)


def test_empty_rules_valid_but_only_review():
    p = copy.deepcopy(POLICY)
    p["rules"] = []
    out = evaluate_snapshot(snapshot(fake_connection()), validate_policy(p))
    assert out["counts"]["review"] == 1


def test_policy_load_roundtrip(tmp_path: Path):
    f = tmp_path / "policy.json"
    f.write_text(json.dumps(POLICY), encoding="utf-8")
    p = load_policy(f)
    assert p["rules"][0]["id"] == "sample-ssh"


def test_policy_load_rejects_duplicate_json_keys(tmp_path: Path):
    f = tmp_path / "policy.json"
    f.write_text('{"schema_version":1,"schema_version":1,"default_action":"review","rules":[]}', encoding="utf-8")
    with pytest.raises(GuardError):
        load_policy(f)


def test_policy_load_rejects_oversized_json(tmp_path: Path):
    f = tmp_path / "policy.json"
    f.write_bytes(b" " * 65537)
    with pytest.raises(GuardError):
        load_policy(f)


def test_evaluator_rejects_non_snapshot():
    with pytest.raises(GuardError):
        evaluate_snapshot({"mode": "enforce", "connections": []}, validate_policy(copy.deepcopy(POLICY)))


def test_policy_does_not_mutate_input():
    p = copy.deepcopy(POLICY)
    original = copy.deepcopy(p)
    validate_policy(p)
    assert p == original


def test_example_policy_loads():
    example = Path(__file__).resolve().parents[1] / "examples" / "network-policy.example.json"
    p = load_policy(example)
    assert len(p["rules"]) == 2


def test_network_plan_cli_uses_only_local_snapshot(monkeypatch, tmp_path: Path, capsys):
    import sys
    from api_privacy_guard import cli
    f = tmp_path / "network-policy.json"
    f.write_text(json.dumps(POLICY), encoding="utf-8")
    calls = []
    def fake_take_snapshot(pid, *, include_children, reveal_addresses):
        calls.append((pid, include_children, reveal_addresses))
        return snapshot(fake_connection())
    monkeypatch.setattr("api_privacy_guard.network_guard.take_snapshot", fake_take_snapshot)
    monkeypatch.setattr(sys, "argv", ["api-privacy-guard", "network-plan", "--pid", "7", "--policy", str(f)])
    cli.main()
    out = json.loads(capsys.readouterr().out)
    assert calls == [(7, True, True)]
    assert out["mode"] == "dry_run_only"
    assert out["counts"]["allow_candidate"] == 1
    assert "192.168.1.25" not in json.dumps(out)
