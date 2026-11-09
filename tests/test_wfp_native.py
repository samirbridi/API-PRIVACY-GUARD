"""Mocked tests; no actual Windows networking or firewall operation."""
from __future__ import annotations
import ctypes
import hashlib
import pytest
from api_privacy_guard.config import GuardError
from api_privacy_guard.wfp_native import (
    FWPM_SESSION0, FWP_BYTE_BLOB, FWPM_SESSION_FLAG_DYNAMIC,
    NativeWfpApi, diagnose,
)

EXE = r"C:\Program Files\TestIDE\agent.exe"
FAKE_SHA = "f" * 64

class FakeApi:
    def __init__(self, failure=False, close_failure=False, empty=False):
        self.calls = []
        self.failure = failure
        self.close_failure = close_failure
        self.empty = empty
    def open_dynamic_session(self):
        self.calls.append("open")
        return 123
    def get_app_id(self, exe):
        self.calls.append(("app", exe))
        if self.failure:
            raise GuardError("Test error")
        return b"" if self.empty else b"FAKE-APP-ID"
    def close_session(self, handle):
        self.calls.append(("close", handle))
        if self.close_failure:
            raise GuardError("Test close error")

def inspect(exe):
    assert exe == EXE
    return {"sha256":FAKE_SHA}

def test_native_session_only_and_no_sensitive_path():
    api = FakeApi()
    result = diagnose(EXE, api=api, platform="win32", inspect=inspect)
    assert result["mode"] == "native_diagnostics_only"
    assert result["session_closed"] is True
    assert result["session_dynamic"] is True
    assert result["firewall_modified"] is False
    assert result["filters_created"] == 0
    assert result["wfp_app_id_sha256_prefix"] == hashlib.sha256(b"FAKE-APP-ID").hexdigest()[:16]
    assert "TestIDE" not in str(result)
    assert api.calls == ["open", ("app", EXE), ("close", 123)]

def test_fail_closed_and_close_on_app_lookup_failure():
    api = FakeApi(failure=True)
    with pytest.raises(GuardError):
        diagnose(EXE, api=api, platform="win32", inspect=inspect)
    assert api.calls[-1] == ("close", 123)

def test_fail_closed_and_close_on_empty_app_blob():
    api = FakeApi(empty=True)
    with pytest.raises(GuardError):
        diagnose(EXE, api=api, platform="win32", inspect=inspect)
    assert api.calls[-1] == ("close", 123)

def test_close_error_reported():
    with pytest.raises(GuardError, match="close error"):
        diagnose(EXE, api=FakeApi(close_failure=True), platform="win32", inspect=inspect)

def test_os_check_stops_before_native_operation():
    api = FakeApi()
    with pytest.raises(GuardError, match="Windows"):
        diagnose(EXE, api=api, platform="linux", inspect=inspect)
    assert api.calls == []

def test_reject_wrong_executable_before_any_native_call():
    api = FakeApi()
    with pytest.raises(GuardError):
        diagnose("../x.exe", api=api, platform="win32", inspect=inspect)
    assert api.calls == []

def test_invalid_fingerprint_fails_before_open():
    api = FakeApi()
    with pytest.raises(GuardError):
        diagnose(EXE, api=api, platform="win32", inspect=lambda _: {"sha256": "bad"})
    assert api.calls == []

def test_ctypes_structure_has_expected_native_fields():
    assert [name for name, _ in FWPM_SESSION0._fields_][2] == "flags"
    assert FWPM_SESSION_FLAG_DYNAMIC == 1
    assert [name for name, _ in FWP_BYTE_BLOB._fields_] == ["size", "data"]
    assert ctypes.sizeof(FWPM_SESSION0) >= 64

def test_native_bindings_not_available_on_linux(monkeypatch):
    import api_privacy_guard.wfp_native as n
    monkeypatch.setattr(n.sys, "platform", "linux")
    with pytest.raises(GuardError, match="Windows"):
        NativeWfpApi()

class FakeFunction:
    def __init__(self, impl):
        self.impl = impl
        self.argtypes = None
        self.restype = None
    def __call__(self, *args):
        return self.impl(*args)


def test_native_dll_call_conventions_and_dynamic_flag(monkeypatch):
    import api_privacy_guard.wfp_native as n
    monkeypatch.setattr(n.sys, "platform", "win32")
    calls=[]
    blobdata=(ctypes.c_ubyte * 4)(1, 2, 3, 4)
    blob=n.FWP_BYTE_BLOB(4, ctypes.cast(blobdata,ctypes.POINTER(ctypes.c_ubyte)))
    pointer=ctypes.pointer(blob)

    def openfn(server, auth, identity, sessionptr, handleptr):
        assert auth == 10
        session=ctypes.cast(sessionptr,ctypes.POINTER(n.FWPM_SESSION0)).contents
        assert session.flags == n.FWPM_SESSION_FLAG_DYNAMIC
        assert session.displayData.name.startswith("API Privacy Guard")
        ctypes.cast(handleptr,ctypes.POINTER(ctypes.c_void_p)).contents.value = 444
        calls.append("open")
        return 0
    def getappid(exe, resultptr):
        assert exe == EXE
        ctypes.cast(resultptr,ctypes.POINTER(ctypes.POINTER(n.FWP_BYTE_BLOB)))[0] = pointer
        calls.append("app")
        return 0
    def freefn(resultptr):
        calls.append("free")
    def closefn(handle):
        assert handle.value == 444
        calls.append("close")
        return 0
    fake = type("FakeDLL", (), {
        "FwpmEngineOpen0": FakeFunction(openfn),
        "FwpmGetAppIdFromFileName0": FakeFunction(getappid),
        "FwpmFreeMemory0": FakeFunction(freefn),
        "FwpmEngineClose0": FakeFunction(closefn),
    })()
    monkeypatch.setattr(n.ctypes, "WinDLL", lambda name, use_last_error: fake, raising=False)
    result=n.diagnose(EXE, platform="win32", inspect=inspect)
    assert result["session_closed"] is True
    assert result["wfp_app_id_size"] == 4
    assert calls == ["open", "app", "free", "close"]


def test_native_dll_appid_error_still_closes_session(monkeypatch):
    import api_privacy_guard.wfp_native as n
    monkeypatch.setattr(n.sys, "platform", "win32")
    calls=[]
    def openfn(a,b,c,d,handleptr):
        ctypes.cast(handleptr,ctypes.POINTER(ctypes.c_void_p)).contents.value=999
        return 0
    def getappid(a,b):
        calls.append("lookup-failed")
        return 5
    def closefn(handle):
        calls.append("close")
        return 0
    fake = type("FakeDLL", (), {
        "FwpmEngineOpen0": FakeFunction(openfn),
        "FwpmGetAppIdFromFileName0": FakeFunction(getappid),
        "FwpmFreeMemory0": FakeFunction(lambda arg: calls.append("free")),
        "FwpmEngineClose0": FakeFunction(closefn),
    })()
    monkeypatch.setattr(n.ctypes, "WinDLL", lambda name, use_last_error: fake, raising=False)
    with pytest.raises(GuardError, match="identificação"):
        n.diagnose(EXE, platform="win32", inspect=inspect)
    assert calls == ["lookup-failed", "close"]
