from api_privacy_guard.config import GuardError, initialize, load, profile, config_path
import pytest


def test_config_default_disabled(tmp_path):
    p = initialize(tmp_path / "cfg.json")
    cfg = load(p)
    assert cfg["ssh_targets"]["demo-debian"]["enabled"] is False
    assert cfg["api_services"]["demo-api"]["enabled"] is False
    with pytest.raises(GuardError):
        profile(cfg, "ssh_targets", "demo-debian")


def test_never_overwrite_configuration(tmp_path):
    p = initialize(tmp_path / "cfg.json")
    with pytest.raises(GuardError):
        initialize(p)


def test_config_env_prefix(monkeypatch, tmp_path):
    expected = tmp_path / "custom-config.json"
    monkeypatch.setenv("API_PRIVACY_GUARD_CONFIG", str(expected))
    assert config_path() == expected.resolve()
