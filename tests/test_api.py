import pytest
from mizin_guard.config import GuardError
from mizin_guard.apibroker import api_location, api_call

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
    monkeypatch.setattr("mizin_guard.apibroker._get_token", lambda name: "FAKE-SECRET-TOKEN-123")
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
    monkeypatch.setattr("mizin_guard.apibroker.urllib.request.build_opener", lambda *args: Opener())
    output = api_call(CFG, "test", "GET", "/status")
    assert "ok" in output
    assert "FAKE-SECRET-TOKEN-123" not in output
    assert observed[0].get_header("Authorization") == "Bearer FAKE-SECRET-TOKEN-123"


def test_api_reject_secret_response(monkeypatch):
    monkeypatch.setattr("mizin_guard.apibroker._get_token", lambda name: "FAKE-SECRET-TOKEN-123")
    class Reply:
        status=200
        def __enter__(self): return self
        def __exit__(self,*exc): return False
        def read(self, n): return b"password=superSecretValue"
    class Opener:
        def open(self, req, timeout): return Reply()
    monkeypatch.setattr("mizin_guard.apibroker.urllib.request.build_opener", lambda *args: Opener())
    with pytest.raises(GuardError): api_call(CFG, "test", "GET", "/status")
