import os
import pytest

@pytest.fixture(autouse=True)
def fake_config_location(tmp_path, monkeypatch):
    monkeypatch.setenv("MIZIN_GUARD_CONFIG", str(tmp_path / "guard-config.json"))
