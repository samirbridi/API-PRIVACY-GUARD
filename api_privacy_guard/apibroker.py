"""HTTP API broker with fixed, administrator-configured HTTPS origin/path scopes."""
from __future__ import annotations
import json
import posixpath
import re
import urllib.error
import urllib.parse
import urllib.request
from .config import GuardError, profile
from .scanner import check_for_model
from .audit import record


def _get_token(name: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name):
        raise GuardError("Nome da credencial inválido.")
    try:
        import keyring
        token = keyring.get_password("APIPrivacyGuard", name)
    except Exception:
        raise GuardError("Cofre do sistema indisponível; operação não autorizada.") from None
    if not token:
        raise GuardError("Token não encontrado no cofre local.")
    if any(x in token for x in ("\r", "\n", "\0")):
        raise GuardError("Token armazenado inválido.")
    return token


def api_location(svc: dict, method: str, path: str) -> str:
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"} or method not in svc.get("methods", []):
        raise GuardError("Método HTTP não autorizado.")
    base = svc.get("base_url", "")
    parsed_base = urllib.parse.urlsplit(base)
    if (parsed_base.scheme != "https" or not parsed_base.hostname or parsed_base.username or
            parsed_base.password or parsed_base.query or parsed_base.fragment or
            not parsed_base.netloc or parsed_base.path.endswith("/../")):
        raise GuardError("A API deve ter uma base HTTPS fixa válida.")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "\\" in path or "#" in path:
        raise GuardError("Caminho HTTP inválido.")
    try:
        parsed_path = urllib.parse.urlsplit(path)
        decoded_path = urllib.parse.unquote(parsed_path.path)
    except ValueError:
        raise GuardError("Caminho HTTP inválido.") from None
    if (not decoded_path.startswith("/") or "//" in decoded_path or "\\" in decoded_path or
            any(x in decoded_path for x in ("\0", "\r", "\n", "?", "#")) or
            posixpath.normpath(decoded_path) != decoded_path.rstrip("/") and decoded_path != "/" or
            any(seg in (".", "..") for seg in decoded_path.split("/"))):
        raise GuardError("Tentativa de contornar a política de caminho HTTP.")
    allow = svc.get("allowed_paths")
    if not isinstance(allow, list) or not any(
        isinstance(prefix, str) and prefix.startswith("/") and prefix != "/" and
        (decoded_path == prefix.rstrip("/") or decoded_path.startswith(prefix.rstrip("/") + "/"))
        for prefix in allow
    ):
        raise GuardError("Caminho HTTP não autorizado para este serviço.")
    # The model only controls the relative path/query; authority stays fixed in the admin profile.
    return base.rstrip("/") + path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_call(cfg: dict, name: str, method: str, path: str, body_json: str = "") -> str:
    svc = profile(cfg, "api_services", name)
    method = method.upper()
    url = api_location(svc, method, path)
    limit = cfg.get("limits", {}).get("max_api_response_bytes", 65536)
    if type(limit) is not int or not 1024 <= limit <= 1048576:
        raise GuardError("Limite de resposta inválido.")
    body = None
    if body_json:
        if len(body_json.encode("utf-8")) > 131072:
            raise GuardError("Corpo de requisição muito grande.")
        try:
            body = json.dumps(json.loads(body_json), ensure_ascii=False).encode("utf-8")
        except (ValueError, TypeError):
            raise GuardError("Informe JSON válido.") from None
    elif method in ("POST", "PUT", "PATCH"):
        body = b"{}"
    if method == "GET" and body is not None:
        raise GuardError("GET não aceita corpo neste conector.")
    auth = svc.get("auth", "bearer")
    if auth not in ("bearer", "x-api-key"):
        raise GuardError("Tipo de autenticação não suportado.")
    token = _get_token(svc.get("token_name", ""))
    headers = {"Accept": "application/json", "Content-Type": "application/json",
               "User-Agent": "APIPrivacyGuard/0.1"}
    if auth == "bearer":
        headers["Authorization"] = "Bearer " + token
    else:
        headers["X-API-Key"] = token
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    record("api_" + method.lower(), name, "attempt", path)
    try:
        with opener.open(req, timeout=20) as resp:
            status = resp.status
            raw = resp.read(limit + 1)
    except urllib.error.HTTPError as exc:
        record("api_" + method.lower(), name, "http_error", path)
        return f"HTTP {exc.code}: serviço retornou erro; corpo omitido por privacidade."
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        record("api_" + method.lower(), name, "transport_error", path)
        raise GuardError("Falha na comunicação HTTPS com o serviço autorizado.") from None
    try:
        output = check_for_model(raw, limit)
    except GuardError:
        record("api_" + method.lower(), name, "blocked_secret_or_size", path)
        raise
    record("api_" + method.lower(), name, "ok", path)
    return f"HTTP {status}\n{output}"
