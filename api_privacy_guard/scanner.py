"""Fail-closed, best-effort secret scanning of data returned to the model.

Pattern matching is not complete DLP. It cannot guarantee no confidential data leaks.
"""
import re
import urllib.parse
from .config import GuardError

PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:[A-Z ]* )?PRIVATE KEY-----", re.I),
    "credential_assignment": re.compile(
        r"(?i)(?:^|[\s{,\"\'])"
        r"(?:password|passwd|pwd|secret|api[_-]?key|(?:access[_-]?|refresh[_-]?|session[_-]?)?token|client[_-]?secret|authorization)"
        r"[\"\']?\s*[:=]\s*[\"\']?[^\s\"\'{};,]{6,}", re.M),
    "bearer": re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]{12,}"),
    "github_token": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    "openai_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{16,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{15,}"),
}

DENIED_NAMES = {".env", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys", "credentials.json", "secrets.json", "known_hosts"}
DENIED_SUFFIXES = (".pem", ".p12", ".pfx", ".key", ".kdbx", ".envrc")


def forbidden_path(path: str) -> bool:
    parts = [p.casefold() for p in path.replace("\\", "/").split("/") if p]
    if ".ssh" in parts or ".aws" in parts or ".gnupg" in parts or ".git" in parts or ".kube" in parts:
        return True
    return any(p in DENIED_NAMES or p.startswith(".env.") or p.endswith(DENIED_SUFFIXES) for p in parts)


def secret_categories(data: str) -> list[str]:
    return [category for category, pattern in PATTERNS.items() if pattern.search(data)]


def check_for_model(data: bytes, max_size: int) -> str:
    if len(data) > max_size:
        raise GuardError("Saída grande demais para retornar ao agente.")
    if b"\0" in data:
        raise GuardError("Saída binária bloqueada: este MVP permite somente texto.")
    try:
        decoded = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise GuardError("Saída não UTF-8 bloqueada.") from None
    matches = secret_categories(decoded)
    if matches:
        raise GuardError("Saída bloqueada por indício de segredo: " + ", ".join(matches))
    return decoded


def check_outbound_api_data(path: str, body: bytes | None, local_token: str) -> None:
    """Best-effort DLP for model-controlled API request data.

    The broker-inserted Authorization header is intentionally *not* scanned:
    it is required for authentication at the explicitly configured destination.
    This gate only screens agent-controlled URL and JSON body data.
    """
    parsed = urllib.parse.urlsplit(path)
    candidate_path = parsed.path
    for _ in range(3):
        if secret_categories(candidate_path) or (local_token and local_token in candidate_path):
            raise GuardError("Bloqueio preventivo: informação sensível no caminho HTTP.")
        candidate_path = urllib.parse.unquote(candidate_path)
    if parsed.query:
        try:
            params = urllib.parse.parse_qsl(
                parsed.query, keep_blank_values=True, max_num_fields=128
            )
        except (ValueError, UnicodeError):
            raise GuardError("Consulta HTTP inválida ou excessivamente grande.") from None
        for key, value in params:
            for _ in range(3):
                candidate = f"{key}={value}"
                if secret_categories(candidate) or (local_token and local_token in candidate):
                    raise GuardError("Bloqueio preventivo: informação sensível na consulta HTTP.")
                key, value = urllib.parse.unquote_plus(key), urllib.parse.unquote_plus(value)
    if body is not None:
        try:
            content = body.decode("utf-8", "strict")
        except UnicodeError:
            raise GuardError("Corpo HTTP não UTF-8.") from None
        if secret_categories(content) or (local_token and local_token in content):
            raise GuardError("Bloqueio preventivo: informação sensível no corpo HTTP.")
