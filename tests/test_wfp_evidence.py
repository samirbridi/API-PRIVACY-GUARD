"""No WFP, firewall, or network calls are made by these tests."""
import copy
import json
import sys
import pytest

from api_privacy_guard.config import GuardError
from api_privacy_guard.wfp_evidence import load_evidence, evaluate_evidence


def sample():
    return {
        "schema_version": 1, "source": "manual_windows_vm_lab",
        "operator_checks": {
            "disposable_vm": True, "isolated_network": True,
            "owned_endpoint": True, "target_executable_used": True,
            "recovery_ready": True, "same_filter_id_in_probe": True,
        },
        "normal_run": {
            "id_line": "APG_FILTER_ID=123456",
            "probe_during": "APG_FILTER_PRESENT=true",
            "probe_after": "APG_FILTER_PRESENT=false",
            "session_closed": "APG_SESSION_CLOSED=true",
            "helper_exit_code": 0,
            "before": "reachable", "during": "blocked", "after": "reachable",
        },
        "crash_run": {
            "id_line": "APG_FILTER_ID=654321",
            "probe_during": "APG_FILTER_PRESENT=true",
            "probe_after": "APG_FILTER_PRESENT=false",
            "after": "reachable",
        },
    }


def test_consistency_does_not_claim_protection():
    out = evaluate_evidence(sample())
    assert out["assessment"] == "reported_checks_consistent"
    assert out["ready_for_production"] is False
    assert out["independently_verified"] is False
    assert out["firewall_modified"] is False
    assert "123456" not in json.dumps(out)


def test_missing_crash_trial_never_succeeds():
    x = sample()
    x["crash_run"] = None
    out = evaluate_evidence(x)
    assert out["assessment"] == "incomplete_or_inconsistent"
    assert "abrupt_termination_not_tested" in out["issues"]


@pytest.mark.parametrize("key,value", [
    ("probe_during", "APG_FILTER_PRESENT=false"),
    ("probe_after", "APG_FILTER_PRESENT=true"),
    ("probe_after", "APG_FILTER_QUERY_ERROR=5 (lookup)"),
    ("session_closed", None),
    ("helper_exit_code", 4),
    ("before", "blocked"),
    ("during", "reachable"),
    ("after", "inconclusive"),
])
def test_normal_failure_detected(key, value):
    x = sample()
    x["normal_run"][key] = value
    assert evaluate_evidence(x)["normal_run_consistent"] is False


@pytest.mark.parametrize("key,value", [
    ("probe_during", "APG_FILTER_PRESENT=false"),
    ("probe_after", "APG_FILTER_PRESENT=true"),
    ("probe_after", "APG_FILTER_QUERY_ERROR=5 (lookup)"),
    ("after", "blocked"),
])
def test_crash_failure_detected(key, value):
    x = sample()
    x["crash_run"][key] = value
    out = evaluate_evidence(x)
    assert out["crash_run_consistent"] is False


def test_reused_id_does_not_pass():
    x = sample()
    x["crash_run"]["id_line"] = x["normal_run"]["id_line"]
    assert "reused_filter_id" in evaluate_evidence(x)["issues"]


def test_missing_disposable_vm_is_not_proof():
    x = sample()
    x["operator_checks"]["disposable_vm"] = False
    assert evaluate_evidence(x)["assessment"] != "reported_checks_consistent"


@pytest.mark.parametrize("mutate", [
    lambda x: x.update(extra="secret"),
    lambda x: x.update(schema_version=True),
    lambda x: x.update(source="remote_ai"),
    lambda x: x["normal_run"].update(token="a secret"),
    lambda x: x["normal_run"].update(id_line="APG_FILTER_ID=0"),
    lambda x: x["normal_run"].update(id_line="APG_FILTER_ID=18446744073709551616"),
    lambda x: x["normal_run"].update(id_line="APG_FILTER_ID=01"),
    lambda x: x["normal_run"].update(id_line="APG_FILTER_ID=12\nsecret"),
    lambda x: x["normal_run"].update(probe_during="APG_FILTER_PRESENT=true\nsecret"),
    lambda x: x["normal_run"].update(helper_exit_code=True),
    lambda x: x["normal_run"].update(after="not recorded"),
    lambda x: x["operator_checks"].update(owned_endpoint="yes"),
])
def test_bad_or_untrusted_input_rejected(mutate):
    x = sample()
    mutate(x)
    with pytest.raises(GuardError):
        evaluate_evidence(x)


def test_file_roundtrip(tmp_path):
    p = tmp_path / "evidence.json"
    p.write_text(json.dumps(sample()), encoding="utf-8")
    assert evaluate_evidence(load_evidence(p))["normal_run_consistent"] is True


def test_duplicate_keys_rejected(tmp_path):
    p = tmp_path / "dupe.json"
    p.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(GuardError):
        load_evidence(p)


def test_oversized_data_rejected(tmp_path):
    p = tmp_path / "large.json"
    p.write_bytes(b" " * 16385)
    with pytest.raises(GuardError):
        load_evidence(p)


def test_cli_only_redacted_result(tmp_path, monkeypatch, capsys):
    from api_privacy_guard import cli
    p = tmp_path / "case.json"
    p.write_text(json.dumps(sample()), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "api-privacy-guard", "wfp-evidence-review", "--file", str(p)])
    cli.main()
    out = json.loads(capsys.readouterr().out)
    assert out["assessment"] == "reported_checks_consistent"
    assert out["ready_for_production"] is False
    assert "APG_FILTER_ID=" not in json.dumps(out)


def test_example_not_reported_success():
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "examples" / "wfp-evidence.example.json"
    assert evaluate_evidence(load_evidence(path))["assessment"] == "incomplete_or_inconsistent"
