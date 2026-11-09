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
# Remote Unix file operations scoped to a pinned directory descriptor.
# Self-contained Python 3 script executed on the destination Linux host.
import os
import stat
import sys

mode, root, requested, max_bytes = sys.argv[1:5]
max_bytes = int(max_bytes)
if mode not in ('read', 'write') or max_bytes < 1:
    sys.exit(46)

# No path from the model is trusted without this independent remote check.
if (not root.startswith('/') or not requested.startswith('/') or
        '\x00' in root or '\x00' in requested or
        '..' in root.split('/') or '..' in requested.split('/')):
    sys.exit(40)
relative = os.path.relpath(requested, root)
parts = relative.split('/')
if (relative in ('.', '..') or relative.startswith('../') or
        any(p in ('', '.', '..') for p in parts)):
    sys.exit(40)

# Open each directory using a directory FD and O_NOFOLLOW; a rename/symlink
# swap cannot redirect the final open to a path outside this pinned root.
flags_dir = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
flags_file = os.O_NOFOLLOW | os.O_NONBLOCK
# Root itself is opened component-by-component; no symlink in the configured
# root or its ancestors may silently redirect the trusted directory.
root_fd = os.open('/', flags_dir)
try:
    root_parts = [component for component in root.split('/') if component]
    if not root_parts or any(component in ('.', '..') for component in root_parts):
        sys.exit(40)
    for component in root_parts:
        next_fd = os.open(component, flags_dir, dir_fd=root_fd)
        os.close(root_fd)
        root_fd = next_fd
    dir_fd = root_fd
    for component in parts[:-1]:
        next_fd = os.open(component, flags_dir, dir_fd=dir_fd)
        if dir_fd != root_fd:
            os.close(dir_fd)
        dir_fd = next_fd
    try:
        flags = flags_file | (os.O_RDONLY if mode == 'read' else os.O_WRONLY)
        fd = os.open(parts[-1], flags, dir_fd=dir_fd)
        try:
            info = os.fstat(fd)
            # Reject nonregular targets and hardlinks to files outside root.
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                sys.exit(45)
            if mode == 'read':
                if info.st_size > max_bytes:
                    sys.exit(42)
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    content = stream.read(max_bytes + 1)
                if len(content) > max_bytes:
                    sys.exit(42)
                sys.stdout.buffer.write(content)
            else:
                # Validate all input before modifying the existing file.
                payload = sys.stdin.buffer.read(max_bytes + 1)
                if len(payload) > max_bytes:
                    sys.exit(42)
                os.ftruncate(fd, 0)
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        sys.exit(47)
                    view = view[written:]
                sys.stdout.write('OK')
        finally:
            os.close(fd)
    finally:
        if dir_fd != root_fd:
            os.close(dir_fd)
finally:
    os.close(root_fd)
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
