"""SSH key-agent broker: sends a command to OpenSSH without exposing keys to MCP.

Remote endpoint must have Python 3 installed. This is NOT an OS sandbox.
"""
from __future__ import annotations
import posixpath
import re
import shlex
import subprocess
from .config import GuardError, profile
from .scanner import forbidden_path, check_for_model
from .audit import record

USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,253}$")

# The remote script is written by this application, never by an agent.
REMOTE_SCRIPT = r'''
import os, sys
mode, root, requested, max_bytes = sys.argv[1:5]
max_bytes = int(max_bytes)
base = os.path.realpath(root)
requested_real = os.path.realpath(requested)
if not os.path.isdir(base) or os.path.commonpath([base, requested_real]) != base:
    sys.exit(40)
if mode == 'read':
    if not os.path.isfile(requested_real):
        sys.exit(41)
    if os.path.getsize(requested_real) > max_bytes:
        sys.exit(42)
    with open(requested_real, 'rb') as stream:
        content = stream.read(max_bytes + 1)
    if len(content) > max_bytes: sys.exit(42)
    sys.stdout.buffer.write(content)
elif mode == 'write':
    if not os.path.isfile(requested_real) and not os.path.isdir(os.path.dirname(requested_real)):
        sys.exit(43)
    if os.path.islink(requested):
        sys.exit(44)
    data = sys.stdin.buffer.read(max_bytes + 1)
    if len(data) > max_bytes: sys.exit(42)
    # Existing files only by default: no unexpected new destination or symlinks.
    if not os.path.isfile(requested_real):
        sys.exit(45)
    with open(requested_real, 'wb') as stream:
        stream.write(data)
    sys.stdout.write('OK')
else: sys.exit(46)
'''


def validate_path(target: dict, requested: str) -> str:
    root = target.get("root", "")
    if not isinstance(root, str) or not root.startswith("/") or root in ("/", "") or ".." in root.split("/"):
        raise GuardError("Raiz SSH inválida; configure diretório específico.")
    if not isinstance(requested, str) or not requested.startswith("/"):
        raise GuardError("Informe um caminho absoluto permitido.")
    if any(c in requested for c in ("\0", "\n", "\r")) or ".." in requested.split("/"):
        raise GuardError("Caminho inválido: controle ou travessia de diretórios.")
    clean_root = posixpath.normpath(root)
    clean_path = posixpath.normpath(requested)
    if clean_path != clean_root and not clean_path.startswith(clean_root + "/"):
        raise GuardError("Caminho fora da raiz permitida.")
    if forbidden_path(clean_path):
        raise GuardError("Acesso negado a arquivo de credenciais.")
    return clean_path


def ssh_command(target: dict, remote_cmd: str) -> list[str]:
    host, user, port = target.get("host"), target.get("user"), target.get("port", 22)
    if not isinstance(host, str) or not HOST_RE.fullmatch(host) or host.startswith("-"):
        raise GuardError("Host SSH inválido.")
    if not isinstance(user, str) or not USER_RE.fullmatch(user) or user.startswith("-"):
        raise GuardError("Usuário SSH inválido.")
    if type(port) is not int or not 1 <= port <= 65535:
        raise GuardError("Porta SSH inválida.")
    return ["ssh", "-T", "-p", str(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1", "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none", f"{user}@{host}", remote_cmd]


def run_ssh(cfg: dict, name: str, mode: str, path: str = "", data: str = "", task: str = "") -> str:
    target = profile(cfg, "ssh_targets", name)
    if mode not in ("read", "write", "task"):
        raise GuardError("Operação desconhecida.")
    if mode in ("read", "write"):
        if target.get(mode) is not True:
            raise GuardError("Operação não habilitada para este destino.")
        path = validate_path(target, path)
        limit = cfg.get("limits", {}).get("max_file_bytes", 65536)
        if type(limit) is not int or not 1024 <= limit <= 1048576:
            raise GuardError("Limite de tamanho inválido.")
        if mode == "write" and len(data.encode("utf-8")) > limit:
            raise GuardError("Arquivo excede o limite autorizado.")
        argv = ["python3", "-c", REMOTE_SCRIPT, mode, target["root"], path, str(limit)]
        remote_cmd = " ".join(shlex.quote(a) for a in argv)
        stdin = data.encode("utf-8") if mode == "write" else None
        resource = path
    else:
        tasks = target.get("tasks", {})
        argv = tasks.get(task) if isinstance(tasks, dict) else None
        if not isinstance(argv, list) or not argv or any(not isinstance(a, str) or not a or "\0" in a or "\n" in a for a in argv):
            raise GuardError("Tarefa não cadastrada ou inválida.")
        # Only pre-registered commands, no arbitrary model-provided shell text.
        remote_cmd = " ".join(shlex.quote(a) for a in argv)
        stdin, resource = None, task
    cmd = ssh_command(target, remote_cmd)
    record("ssh_" + mode, name, "attempt", resource)
    try:
        result = subprocess.run(cmd, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=40, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        record("ssh_" + mode, name, "error", resource)
        raise GuardError("Falha na execução SSH (timeout/cliente indisponível).") from None
    if result.returncode:
        record("ssh_" + mode, name, "error", resource)
        raise GuardError(f"Operação SSH recusada ou falhou (código {result.returncode}). Verifique SSH e permissões.")
    if mode == "write":
        record("ssh_" + mode, name, "ok", resource)
        return "Arquivo existente atualizado por SSH."
    size_limit = cfg.get("limits", {}).get("max_file_bytes", 65536)
    if mode == "task":
        # Limit task outputs too.
        size_limit = min(int(size_limit), 65536)
    try:
        response = check_for_model(result.stdout, size_limit)
    except GuardError:
        record("ssh_" + mode, name, "blocked_secret_or_size", resource)
        raise
    record("ssh_" + mode, name, "ok", resource)
    return response
