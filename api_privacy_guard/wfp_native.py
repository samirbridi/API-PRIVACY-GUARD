"""Windows-native WFP *diagnostics* for dynamic sessions and ALE app identities.

Security boundary: never creates a sublayer, filter, rule, persistent object,
packet capture, or DNS/network request. No enforcement commands exist here.
The native binding is exercised by fakes on non-Windows CI and requires
Windows integration testing before building a real filtering backend.
"""
from __future__ import annotations

import ctypes
import hashlib
import sys
import re
from typing import Protocol

from .config import GuardError
from .wfp_preflight import fingerprint, validate_path

RPC_C_AUTHN_WINNT = 10
FWPM_SESSION_FLAG_DYNAMIC = 0x00000001
MAX_APP_ID_BYTES = 65536


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8),
    ]


class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [("name", ctypes.c_wchar_p), ("description", ctypes.c_wchar_p)]


class FWPM_SESSION0(ctypes.Structure):
    _fields_ = [
        ("sessionKey", GUID), ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", ctypes.c_uint32), ("txnWaitTimeoutInMSec", ctypes.c_uint32),
        ("processId", ctypes.c_uint32), ("sid", ctypes.c_void_p),
        ("username", ctypes.c_wchar_p), ("kernelMode", ctypes.c_int32),
    ]


class FWP_BYTE_BLOB(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]


class WfpApi(Protocol):
    def open_dynamic_session(self) -> int: ...
    def get_app_id(self, executable: str) -> bytes: ...
    def close_session(self, handle: int) -> None: ...


class NativeWfpApi:
    """Thin Windows-only ctypes bindings; no write-capable WFP function loaded."""
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise GuardError("API WFP nativa disponível somente no Windows.")
        try:
            dll = ctypes.WinDLL("fwpuclnt.dll", use_last_error=True)
        except (OSError, AttributeError):
            raise GuardError("Não foi possível carregar fwpuclnt.dll.") from None
        self._open = dll.FwpmEngineOpen0
        self._open.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.POINTER(FWPM_SESSION0), ctypes.POINTER(ctypes.c_void_p),
        ]
        self._open.restype = ctypes.c_uint32
        self._close = dll.FwpmEngineClose0
        self._close.argtypes = [ctypes.c_void_p]
        self._close.restype = ctypes.c_uint32
        self._app_id = dll.FwpmGetAppIdFromFileName0
        self._app_id.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.POINTER(FWP_BYTE_BLOB))]
        self._app_id.restype = ctypes.c_uint32
        self._free = dll.FwpmFreeMemory0
        self._free.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        self._free.restype = None

    def open_dynamic_session(self) -> int:
        session = FWPM_SESSION0()
        session.displayData.name = "API Privacy Guard diagnostic"
        session.displayData.description = "Ephemeral WFP diagnostic session; no filters installed"
        session.flags = FWPM_SESSION_FLAG_DYNAMIC
        handle = ctypes.c_void_p()
        rc = self._open(None, RPC_C_AUTHN_WINNT, None, ctypes.byref(session), ctypes.byref(handle))
        if rc or not handle.value:
            raise GuardError(f"Não foi possível abrir a sessão WFP temporária (código 0x{rc:08X}).")
        return int(handle.value)

    def get_app_id(self, executable: str) -> bytes:
        # The returned blob contains a device path and is never exposed to the model.
        pointer = ctypes.POINTER(FWP_BYTE_BLOB)()
        try:
            rc = self._app_id(executable, ctypes.byref(pointer))
            if rc or not pointer:
                raise GuardError(f"Falha na identificação WFP do executável (código 0x{rc:08X}).")
            blob = pointer.contents
            if not (0 < blob.size <= MAX_APP_ID_BYTES) or not blob.data:
                raise GuardError("WFP retornou identificador de aplicativo inválido.")
            return ctypes.string_at(blob.data, blob.size)
        finally:
            if pointer:
                self._free(ctypes.cast(ctypes.byref(pointer), ctypes.POINTER(ctypes.c_void_p)))

    def close_session(self, handle: int) -> None:
        if type(handle) is not int or handle <= 0:
            raise GuardError("Identificador de sessão WFP inválido.")
        rc = self._close(ctypes.c_void_p(handle))
        if rc:
            raise GuardError(f"Falha ao encerrar a sessão WFP (código 0x{rc:08X}).")


def diagnose(
    executable: str,
    *,
    api: WfpApi | None = None,
    platform: str | None = None,
    inspect=None,
) -> dict:
    """Return non-sensitive metadata; always close session even if AppID lookup fails.

    This diagnostic does NOT verify that a specific running PID uses the given
    executable, nor that its future children will share the same identity.
    """
    validate_path(executable)
    if (sys.platform if platform is None else platform) != "win32":
        raise GuardError("Diagnóstico WFP nativo exige Windows.")
    observed = (fingerprint if inspect is None else inspect)(executable)
    if (not isinstance(observed, dict) or not isinstance(observed.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", observed["sha256"])):
        raise GuardError("Fingerprint local inválido.")
    driver = NativeWfpApi() if api is None else api
    handle = driver.open_dynamic_session()
    if type(handle) is not int or handle <= 0:
        raise GuardError("WFP retornou sessão inválida.")
    try:
        identifier = driver.get_app_id(executable)
        if not isinstance(identifier, bytes) or not (0 < len(identifier) <= MAX_APP_ID_BYTES):
            raise GuardError("Identificador WFP inválido.")
        result = {
            "mode": "native_diagnostics_only", "platform": "win32",
            "session_dynamic": True, "session_closed": False,
            "firewall_modified": False, "filters_created": 0,
            "executable_sha256": observed["sha256"],
            "wfp_app_id_size": len(identifier),
            "wfp_app_id_sha256_prefix": hashlib.sha256(identifier).hexdigest()[:16],
            "warning": "No WFP filter has been installed; there is no network protection yet.",
        }
    finally:
        # An exception from close is not ignored: the caller must know cleanup failed.
        driver.close_session(handle)
    result["session_closed"] = True
    return result
