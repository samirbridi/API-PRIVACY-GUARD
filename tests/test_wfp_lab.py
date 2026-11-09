"""Lab planner tests: no real Windows networking, WFP writes or subprocesses."""
from __future__ import annotations

import copy
from pathlib import Path
import pytest
from api_privacy_guard.config import GuardError
from api_privacy_guard.wfp_lab import prepare_lab_command

EXE = r"C:\Lab\FakeIDE\agent.exe"
HELPER = r"C:\Lab\APIPrivacyGuard\wfp_lab_block.exe"
BASE = {"schema_version": 1, "mode": "preview_only", "rules": [{
    "id": "labone", "executable": EXE, "sha256": "a" * 64,
    "protocol": "tcp", "remote_ip": "8.8.8.8", "remote_port": 443,
}]}


def inspect(path):
    return {"sha256": "a" * 64 if path == EXE else "b" * 64}


def plan(proposal=None, **kwargs):
    return prepare_lab_command(
        BASE if proposal is None else proposal, HELPER,
        platform="win32", vm_acknowledged=True, inspect=inspect, **kwargs,
    )


def test_manual_plan_never_executes():
    x = plan()
    assert x["mode"] == "manual_lab_command_only"
    assert x["filters_installed"] == 0
    assert x["executed"] is False
    assert x["command_argv"][0] == HELPER
    assert x["command_argv"][2:4] == ["--exe", EXE]
    assert x["environment_required"]["APG_WFP_DISPOSABLE_VM"] == "I_ACCEPT_VM_ONLY_LAB"


def test_vm_confirmation_required_before_inspection():
    calls = []
    with pytest.raises(GuardError, match="VM"):
        prepare_lab_command(BASE, HELPER, platform="win32",
                            inspect=lambda p: calls.append(p))
    assert not calls


@pytest.mark.parametrize("duration", [0, 4, 31, 3600, True, 5.2])
def test_duration_limits(duration):
    with pytest.raises(GuardError):
        plan(seconds=duration)


def test_ipv6_denied():
    p = copy.deepcopy(BASE)
    p["rules"][0]["remote_ip"] = "2606:4700:4700::1111"
    with pytest.raises(GuardError, match="IPv4"):
        plan(p)


def test_multiple_rules_denied():
    p = copy.deepcopy(BASE)
    p["rules"].append({**p["rules"][0], "id": "two"})
    with pytest.raises(GuardError, match="exatamente uma"):
        plan(p)


def test_hash_mismatch_denied():
    with pytest.raises(GuardError, match="SHA-256"):
        prepare_lab_command(BASE, HELPER, vm_acknowledged=True, platform="win32",
                            inspect=lambda path: {"sha256": "f" * 64})


def test_linux_denied():
    with pytest.raises(GuardError, match="Windows"):
        prepare_lab_command(BASE, HELPER, vm_acknowledged=True, platform="linux",
                            inspect=inspect)


def test_wrong_helper_denied():
    with pytest.raises(GuardError, match="auxiliar"):
        prepare_lab_command(BASE, r"C:\Lab\untrusted.exe",
                            vm_acknowledged=True, platform="win32", inspect=inspect)


def test_private_ip_denied():
    p = copy.deepcopy(BASE)
    p["rules"][0]["remote_ip"] = "192.168.1.2"
    with pytest.raises(GuardError):
        plan(p)


def test_native_source_has_all_scope_guards_and_dynamic_cleanup():
    source = (Path(__file__).resolve().parents[1] /
              "native" / "wfp_lab_block.cpp").read_text(encoding="utf-8")
    for signature in (
        "FWPM_SESSION_FLAG_DYNAMIC", "FWPM_CONDITION_ALE_APP_ID",
        "FWPM_CONDITION_IP_REMOTE_ADDRESS", "FWPM_CONDITION_IP_REMOTE_PORT",
        "FWPM_CONDITION_IP_PROTOCOL", "FwpmFilterAdd0",
        "FwpmTransactionBegin0", "FwpmTransactionCommit0",
        "FwpmTransactionAbort0", "FwpmEngineClose0",
        "APG_WFP_DISPOSABLE_VM", "LAB-ONLY-EPHEMERAL-BLOCK",
    ):
        assert signature in source
    assert "FWPM_FILTER_FLAG_PERSISTENT" not in source
    assert "FWPM_FILTER_FLAG_BOOTTIME" not in source
