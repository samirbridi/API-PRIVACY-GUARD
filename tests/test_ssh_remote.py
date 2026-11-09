"""Local subprocess simulations of the exact Python program run on Linux SSH hosts."""
import os
import subprocess
import sys

import pytest

from api_privacy_guard.sshbroker import REMOTE_SCRIPT

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Remote target is Unix/Linux")


def invoke(mode, root, path, data=b""):
    return subprocess.run(
        [sys.executable, "-c", REMOTE_SCRIPT, mode, str(root), str(path), "1024"],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=3,
    )


def test_remote_read_existing_nested_file(tmp_path):
    root = tmp_path / "root"
    file = root / "src" / "main.py"
    file.parent.mkdir(parents=True)
    file.write_bytes(b"print('safe')\n")
    r = invoke("read", root, file)
    assert r.returncode == 0 and r.stdout == b"print('safe')\n"


def test_remote_write_existing_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    file = root / "code.py"
    file.write_bytes(b"old")
    r = invoke("write", root, file, b"new")
    assert r.returncode == 0 and r.stdout == b"OK"
    assert file.read_bytes() == b"new"


def test_remote_rejects_symlink_to_file_outside(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"PRIVATE")
    alias = root / "alias.txt"
    alias.symlink_to(secret)
    for mode in ("read", "write"):
        r = invoke(mode, root, alias, b"overwrite")
        assert r.returncode != 0
    assert secret.read_bytes() == b"PRIVATE"


def test_remote_rejects_directory_symlink_outside(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    file = outside / "secret.txt"
    file.write_bytes(b"PRIVATE")
    (root / "alias").symlink_to(outside, target_is_directory=True)
    assert invoke("read", root, root / "alias" / "secret.txt").returncode != 0
    assert invoke("write", root, root / "alias" / "secret.txt", b"oops").returncode != 0
    assert file.read_bytes() == b"PRIVATE"


def test_remote_rejects_hardlinked_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "sensitive.txt"
    outside.write_bytes(b"SECRET")
    (root / "link.txt").hardlink_to(outside)
    assert invoke("read", root, root / "link.txt").returncode != 0
    assert invoke("write", root, root / "link.txt", b"oops").returncode != 0
    assert outside.read_bytes() == b"SECRET"


def test_remote_rejects_nonexistent_write(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    missing = root / "not-created.txt"
    r = invoke("write", root, missing, b"anything")
    assert r.returncode != 0
    assert not missing.exists()


def test_remote_oversized_write_preserves_existing_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    file = root / "code.py"
    file.write_bytes(b"PREVIOUS")
    r = invoke("write", root, file, b"X" * 1025)
    assert r.returncode != 0
    assert file.read_bytes() == b"PREVIOUS"


def test_remote_rejects_parent_directory_traversal(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    other = tmp_path / "other.txt"
    other.write_bytes(b"HIDDEN")
    traversal = str(root) + "/../other.txt"
    assert invoke("read", root, traversal).returncode != 0


def test_remote_rejects_fifo_without_hanging(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    pipe = root / "pipe"
    os.mkfifo(pipe)
    assert invoke("read", root, pipe).returncode != 0
    assert invoke("write", root, pipe, b"data").returncode != 0


def test_remote_rejects_symlink_even_when_pointing_inside(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    file = root / "file.txt"
    file.write_bytes(b"SAFE")
    (root / "alias").symlink_to(file)
    assert invoke("read", root, root / "alias").returncode != 0
    assert invoke("read", root, file).returncode == 0


def test_remote_rejects_symlinked_root(tmp_path):
    real_root = tmp_path / "real"
    real_root.mkdir()
    file = real_root / "main.py"
    file.write_bytes(b"safe")
    root_alias = tmp_path / "alias"
    root_alias.symlink_to(real_root, target_is_directory=True)
    assert invoke("read", root_alias, root_alias / "main.py").returncode != 0
    assert invoke("read", real_root, file).returncode == 0
