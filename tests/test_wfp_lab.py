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
    "protocol": "tcp", "remote_ip": "192.168.56.20", "remote_port": 443,
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


def test_public_ip_denied_in_lab():
    p = copy.deepcopy(BASE)
    p["rules"][0]["remote_ip"] = "8.8.8.8"
    with pytest.raises(GuardError, match="RFC1918"):
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


def test_helper_exposes_runtime_id_and_checked_session_close():
    source = (Path(__file__).resolve().parents[1] / "native" / "wfp_lab_block.cpp").read_text(encoding="utf-8")
    assert "FwpmFilterAdd0(engine.handle, &filter, nullptr, &filter_id)" in source
    assert "APG_FILTER_ID=" in source
    assert 'check(FwpmEngineClose0(engine.handle), "FwpmEngineClose0")' in source
    assert source.index("check(FwpmEngineClose0(engine.handle)") < source.index("APG_SESSION_CLOSED=true")


def test_probe_is_read_only_and_errors_are_not_absence():
    source = (Path(__file__).resolve().parents[1] / "native" / "wfp_lab_probe.cpp").read_text(encoding="utf-8")
    assert "FwpmFilterGetById0" in source
    assert "FwpmFreeMemory0" in source
    assert "FWP_E_FILTER_NOT_FOUND" in source
    assert "APG_FILTER_QUERY_ERROR=" in source
    for forbidden in ("FwpmFilterAdd0", "FwpmFilterDeleteById0", "FwpmSubLayerAdd0", "FwpmTransactionBegin0"):
        assert forbidden not in source


def test_ci_compiles_probe_without_running_it():
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "wfp-lab-compile.yml").read_text(encoding="utf-8")
    assert r"native\wfp_lab_probe.cpp" in workflow
    assert "apg_wfp_lab_probe.exe" in workflow
    assert "Neither executable is executed" in workflow


def test_native_helper_receives_approved_sha256_pin():
    plan_data = plan()
    argv = plan_data["command_argv"]
    assert argv[4:6] == ["--sha256", "a" * 64]
    assert argv[6:8] == ["--ip", "192.168.56.20"]


def test_native_hash_check_occurs_before_wfp_filter_setup():
    source = (Path(__file__).resolve().parents[1] / "native" / "wfp_lab_block.cpp").read_text(encoding="utf-8")
    assert 'std::wcscmp(argv[4], L"--sha256")' in source
    assert 'std::wstring expected_hash(argv[5]);' in source
    assert "ReadonlyExecutable target(exe);" in source
    assert "sha256_open_file(target.file) != expected_hash" in source
    assert source.index("sha256_open_file(target.file)") < source.index("FwpmEngineOpen0(")
    assert source.index("sha256_open_file(target.file)") < source.index("FwpmFilterAdd0(")
    assert "FILE_SHARE_READ" in source
    assert "FILE_FLAG_OPEN_REPARSE_POINT" in source
    assert "GetFinalPathNameByHandleW" in source
    assert "CryptAcquireContextW" in source
    assert "CryptCreateHash" in source
    assert "CryptHashData" in source
    assert "CryptGetHashParam" in source


def test_native_build_links_cryptoapi():
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "wfp-lab-compile.yml").read_text(encoding="utf-8")
    assert "advapi32.lib" in workflow


@pytest.mark.parametrize("ip", ["10.20.30.40", "172.16.1.2", "172.31.254.254", "192.168.56.20"])
def test_private_lab_destinations_are_accepted(ip):
    p = copy.deepcopy(BASE)
    p["rules"][0]["remote_ip"] = ip
    assert plan(p)["command_argv"][7] == ip


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "127.0.0.1", "169.254.1.2",
                                  "100.64.1.1", "172.32.0.1", "192.0.2.1", "192.169.0.1",
                                  "224.0.0.1", "0.0.0.0", "::1", "2001:db8::1"])
def test_non_rfc1918_blocked_in_lab(ip):
    p = copy.deepcopy(BASE)
    p["rules"][0]["remote_ip"] = ip
    with pytest.raises(GuardError):
        plan(p)


def test_lab_private_json_requires_explicit_validation(tmp_path):
    import json
    from api_privacy_guard.wfp_preflight import load
    p = tmp_path / "private-proposal.json"
    p.write_text(json.dumps(BASE), encoding="utf-8")
    with pytest.raises(GuardError):
        load(p)
    assert load(p, lab_private_only=True)["rules"][0]["remote_ip"] == "192.168.56.20"


def test_native_helper_only_targets_rfc1918():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "native" / "wfp_lab_block.cpp").read_text(encoding="utf-8")
    assert "static bool lab_private_ipv4" in source
    assert "!lab_private_ipv4(host_ip)" in source
    assert "public_ipv4" not in source


def test_tcp_lab_client_is_scoped_and_sends_no_data():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "native" / "wfp_lab_connect.cpp").read_text(encoding="utf-8")
    assert "static bool lab_private_ipv4" in source
    assert "APG_TEST_CONNECT=" in source
    assert "IPPROTO_TCP" in source
    assert "select(" in source
    assert "send(" not in source
    assert "WSAStartup" in source


def test_lab_private_example_is_valid_only_in_lab():
    from pathlib import Path
    from api_privacy_guard.wfp_preflight import load
    path = Path(__file__).resolve().parents[1] / "examples" / "wfp-lab-private.example.json"
    assert load(path, lab_private_only=True)["rules"][0]["remote_ip"] == "192.168.56.20"
    with pytest.raises(GuardError):
        load(path)


def test_lab_connect_compiled_but_never_executed_in_ci():
    from pathlib import Path
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "wfp-lab-compile.yml").read_text(encoding="utf-8")
    assert r"native\wfp_lab_connect.cpp" in workflow
    assert "apg_wfp_lab_connect.exe" in workflow
    assert "All three executables are compiled" in workflow
