import pytest
from api_privacy_guard.config import GuardError
from api_privacy_guard.apibroker import api_location, api_call

CFG = {
 "schema_version": 1, "ssh_targets": {},
 "api_services": {"test": {"enabled": True, "base_url": "https://example.com/api/v1",
  "token_name": "dummy", "auth": "bearer", "methods": ["GET", "POST"], "allowed_paths": ["/deploy", "/status"]}},
 "limits": {"max_api_response_bytes": 65536}
}

@pytest.mark.parametrize("path", ["//attacker.com", "/../admin", "/%2e%2e/admin", "/status/%2Fadmin", "/secret", "/status/../../../secret", "http://example.com/status"])
def test_api_paths_reject(path):
    with pytest.raises(GuardError):
        api_location(CFG["api_services"]["test"], "GET", path)


def test_api_path_allow():
    assert api_location(CFG["api_services"]["test"], "GET", "/status?limit=2") == "https://example.com/api/v1/status?limit=2"


def test_api_scope_method():
    with pytest.raises(GuardError):
        api_location(CFG["api_services"]["test"], "DELETE", "/deploy")


def test_api_token_used_only_on_local_http_request(monkeypatch):
    monkeypatch.setattr("api_privacy_guard.apibroker._get_token", lambda name: "FAKE-SECRET-TOKEN-123")
    observed = []
    class Reply:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *exc): return False
        def read(self, max_bytes): return b'{"ok":true}'
    class Opener:
        def open(self, request, timeout):
            observed.append(request)
            return Reply()
    monkeypatch.setattr("api_privacy_guard.apibroker.urllib.request.build_opener", lambda *args: Opener())
    output = api_call(CFG, "test", "GET", "/status")
    assert "ok" in output
    assert "FAKE-SECRET-TOKEN-123" not in output
    assert observed[0].get_header("Authorization") == "Bearer FAKE-SECRET-TOKEN-123"


def test_api_reject_secret_response(monkeypatch):
    monkeypatch.setattr("api_privacy_guard.apibroker._get_token", lambda name: "FAKE-SECRET-TOKEN-123")
    class Reply:
        status=200
        def __enter__(self): return self
        def __exit__(self,*exc): return False
        def read(self, n): return b"password=superSecretValue"
    class Opener:
        def open(self, req, timeout): return Reply()
    monkeypatch.setattr("api_privacy_guard.apibroker.urllib.request.build_opener", lambda *args: Opener())
    with pytest.raises(GuardError): api_call(CFG, "test", "GET", "/status")


@pytest.mark.parametrize("path,body", [
    ("/status?token=abcdefghi123456", ""),
    ("/deploy/FAKE-SECRET-TOKEN-123", ""),
    ("/deploy/ghp_abcdefghijklmnopqrstuvwxyz012345", ""),
    ("/deploy/%46AKE-SECRET-TOKEN-123", ""),
    ("/status?token%3Dabcdefghi123456", ""),
    ("/status?token=%2561bcdefghi123456", ""),
    ("/deploy", '{"password":"superSecretValue"}'),
    ("/deploy", '{"config":{"api_key":"abcdefgh1234567"}}'),
    ("/deploy", '{"data":"FAKE-SECRET-TOKEN-123"}'),
    ("/status?payload=FAKE-SECRET-TOKEN-123", ""),
])
def test_api_blocks_sensitive_outbound_before_http(monkeypatch, path, body):
    monkeypatch.setattr(
        "api_privacy_guard.apibroker._get_token",
        lambda name: "FAKE-SECRET-TOKEN-123"
    )
    calls = []
    monkeypatch.setattr(
        "api_privacy_guard.apibroker.urllib.request.build_opener",
        lambda *args: calls.append(args)
    )
    method = "POST" if body else "GET"
    with pytest.raises(GuardError):
        api_call(CFG, "test", method, path, body)
    assert calls == [], "Transport must not be constructed when outbound DLP blocks."


def test_api_allows_normal_outbound_body(monkeypatch):
    monkeypatch.setattr(
        "api_privacy_guard.apibroker._get_token",
        lambda name: "FAKE-SECRET-TOKEN-123"
    )
    calls = []
    class Reply:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *exc): return False
        def read(self, size): return b'{"ok":true}'
    class Opener:
        def open(self, req, timeout):
            calls.append(req)
            return Reply()
    monkeypatch.setattr(
        "api_privacy_guard.apibroker.urllib.request.build_opener",
        lambda *args: Opener()
    )
    out = api_call(
        CFG, "test", "POST", "/deploy?dry_run=1", '{"version":"0.1.1","message":"Deploy test"}'
    )
    assert "ok" in out
    assert len(calls) == 1
