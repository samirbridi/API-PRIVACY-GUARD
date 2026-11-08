from mizin_guard.config import GuardError, initialize, load, profile
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
