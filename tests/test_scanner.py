import pytest
from mizin_guard.config import GuardError
from mizin_guard.scanner import check_for_model, forbidden_path, secret_categories

@pytest.mark.parametrize("content", [
    b"password=superSecretValue",
    b"api_key: abcdefghijklmnopqrstuvwxyz",
    b'{"token": "abcdefghijklmnop"}',
    b"password = 'strongPassword123'",
    b"Authorization: Bearer abcdefghijklmnop",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"ghp_abcdefghijklmnopqrstuvwxyz012345",
    b"sk-proj-abcdefghijklmnopqrstuvwxyz",
])
def test_blocks_common_secrets(content):
    with pytest.raises(GuardError):
        check_for_model(content, 65536)

@pytest.mark.parametrize("path", ["/srv/app/.env", "/srv/app/.env.production", "/srv/app/.ssh/id_rsa", "/srv/app/.git/config", "/srv/app/token.pem"])
def test_forbidden_paths(path):
    assert forbidden_path(path)


def test_allows_normal_code():
    assert check_for_model(b"print('hello world')\n", 65536) == "print('hello world')\n"


def test_blocks_binary_and_size():
    with pytest.raises(GuardError): check_for_model(b"a\0b", 65536)
    with pytest.raises(GuardError): check_for_model(b"x" * 30, 20)
