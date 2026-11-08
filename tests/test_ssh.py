import subprocess
import pytest
from api_privacy_guard.config import GuardError
from api_privacy_guard.sshbroker import run_ssh, validate_path, ssh_command

CFG = {
    "schema_version": 1,
    "ssh_targets": {"machine": {"enabled": True, "host": "debian.internal", "user": "deploy", "port": 22,
                 "root": "/srv/project", "read": True, "write": True,
                 "tasks": {"git-status": ["git", "-C", "/srv/project", "status", "--short"]}}},
    "api_services": {}, "limits": {"max_file_bytes": 65536}
}

@pytest.mark.parametrize("bad", [
    "/etc/passwd", "/srv/project/../../etc/passwd", "/srv/project-other/a",
    "/srv/project/.env", "/srv/project/.git/config", "../foo", "/srv/project/x\nmalicious"
])
def test_path_deny(bad):
    with pytest.raises(GuardError): validate_path(CFG["ssh_targets"]["machine"], bad)


def test_path_valid():
    assert validate_path(CFG["ssh_targets"]["machine"], "/srv/project/src/main.py") == "/srv/project/src/main.py"


def test_ssh_defensive_options():
    cmd = ssh_command(CFG["ssh_targets"]["machine"], "true")
    assert "BatchMode=yes" in cmd and "StrictHostKeyChecking=yes" in cmd
    assert "ForwardAgent=no" in cmd and "ProxyCommand=none" in cmd


def test_read_output(monkeypatch):
    calls = []
    def mock_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout=b"def foo(): return 1\n", stderr=b"")
    monkeypatch.setattr("api_privacy_guard.sshbroker.subprocess.run", mock_run)
    result = run_ssh(CFG, "machine", "read", path="/srv/project/a.py")
    assert "def foo" in result
    assert "ssh" == calls[0][0][0]


def test_write_uses_stdin_not_command_or_logs(monkeypatch):
    calls = []
    def mock_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout=b"OK", stderr=b"")
    monkeypatch.setattr("api_privacy_guard.sshbroker.subprocess.run", mock_run)
    payload = "print('local-only-test-payload-123')"
    result = run_ssh(CFG, "machine", "write", path="/srv/project/a.py", data=payload)
    assert "atualizado" in result
    assert payload.encode() == calls[0][1]["input"]
    assert payload not in " ".join(calls[0][0])


def test_ssh_model_cannot_run_unregistered_command(monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("SSH must not start")
    monkeypatch.setattr("api_privacy_guard.sshbroker.subprocess.run", forbidden)
    with pytest.raises(GuardError):
        run_ssh(CFG, "machine", "task", task="cat /etc/shadow")


def test_secret_in_ssh_output_not_returned(monkeypatch):
    def mock_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=b"password=superSecretValue", stderr=b"")
    monkeypatch.setattr("api_privacy_guard.sshbroker.subprocess.run", mock_run)
    with pytest.raises(GuardError):
        run_ssh(CFG, "machine", "read", path="/srv/project/a.txt")
