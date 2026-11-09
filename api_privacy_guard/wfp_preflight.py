"""Read-only Windows Filtering Platform preflight. NEVER applies firewall changes."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import ntpath
import re
import sys
from pathlib import Path
from .config import GuardError

PATH = re.compile(r"^[A-Za-z]:\\")
RULE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FIELDS = {"id", "executable", "sha256", "protocol", "remote_ip", "remote_port"}

def validate_path(path):
    if not isinstance(path, str) or len(path) > 512 or not PATH.match(path):
        raise GuardError("Caminho Windows absoluto de executável obrigatório.")
    if any(x in path for x in ('\x00', '\r', '\n', '/', '*', '?', '"', '<', '>', '|')):
        raise GuardError("Caminho de executável inválido.")
    if ':' in path[2:] or any(x in ('', '.', '..') or x.endswith(('.', ' ')) for x in path[3:].split('\\')):
        raise GuardError("Caminho ambíguo, travessia ou ADS não permitido.")
    if not path.lower().endswith('.exe') or ntpath.normpath(path) != path:
        raise GuardError("Requer arquivo .exe em caminho canônico.")
    return path

def validate(data):
    if not isinstance(data, dict) or set(data) != {'schema_version', 'mode', 'rules'}:
        raise GuardError("Formato de proposta WFP inválido.")
    if type(data['schema_version']) is not int or data['schema_version'] != 1 or data['mode'] != 'preview_only':
        raise GuardError("Somente preview_only está disponível.")
    rules = data['rules']
    if not isinstance(rules, list) or not 1 <= len(rules) <= 32:
        raise GuardError("1 a 32 regras obrigatórias.")
    ids = set()
    result = []
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != FIELDS:
            raise GuardError("Regra inválida ou incompleta.")
        name = rule['id']
        if not isinstance(name, str) or not RULE_ID.fullmatch(name) or name in ids:
            raise GuardError("ID de regra inválido/duplicado.")
        ids.add(name)
        exe = validate_path(rule['executable'])
        digest = rule['sha256']
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise GuardError("SHA-256 completo necessário.")
        proto = rule['protocol']
        if type(proto) is not str or proto not in ('tcp', 'udp'):
            raise GuardError("Protocolo deve ser tcp/udp.")
        port = rule['remote_port']
        if type(port) is not int or not 1 <= port <= 65535:
            raise GuardError("Porta remota inválida.")
        target = rule['remote_ip']
        if not isinstance(target, str) or '%' in target or '/' in target or len(target) > 45:
            raise GuardError("É obrigatório IP único e canônico.")
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            raise GuardError("IP inválido.") from None
        if ip.compressed != target.lower() or not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise GuardError("Somente IP público unicast individual nesta fase.")
        result.append({**rule, 'ip_version': ip.version})
    return result

def load(path):
    try:
        with Path(path).expanduser().open('rb') as f:
            raw = f.read(65537)
        if len(raw) > 65536:
            raise GuardError("Arquivo de proposta excede 64 KiB.")
        def unique(pairs):
            data = {}
            for key, value in pairs:
                if key in data:
                    raise GuardError("Chave JSON duplicada.")
                data[key] = value
            return data
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except GuardError:
        raise
    except (OSError, UnicodeError, ValueError):
        raise GuardError("Não foi possível ler a proposta.") from None
    validate(value)
    return value

def fingerprint(path):
    """Local hash pin is a review aid, NOT an immutable Windows process identity."""
    validate_path(path)
    if sys.platform != 'win32':
        raise GuardError("Requer Windows para verificar executável real.")
    file = Path(path)
    try:
        if not file.is_file() or file.is_symlink():
            raise GuardError("Executável inexistente ou symlink.")
        if ntpath.normcase(str(file.resolve(strict=True))) != ntpath.normcase(path):
            raise GuardError("Executável redirecionado; revise caminho.")
        before = file.stat()
        if not 0 < before.st_size <= 256 * 1024 * 1024:
            raise GuardError("Executável acima do limite ou vazio.")
        h = hashlib.sha256()
        with file.open('rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                h.update(chunk)
        after = file.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise GuardError("Executável alterado durante inspeção.")
        return {'name': ntpath.basename(path), 'sha256': h.hexdigest(), 'size_bytes': after.st_size}
    except GuardError:
        raise
    except OSError:
        raise GuardError("Falha ao ler executável local.") from None

def preview(data, inspect=None):
    """Return design only: no WFP session, network access, subprocess or registry."""
    inspect = inspect if inspect is not None else fingerprint
    rows = validate(data)
    seen = {}
    result = []
    for row in rows:
        exe = row['executable']
        if exe not in seen:
            seen[exe] = inspect(exe)
        if not isinstance(seen[exe], dict) or seen[exe].get('sha256') != row['sha256']:
            raise GuardError("Executável difere do SHA-256 aprovado.")
        result.append({
            'rule_id': row['id'], 'candidate_action': 'block_review_only',
            'layer': 'FWPM_LAYER_ALE_AUTH_CONNECT_V' + str(row['ip_version']),
            'app_id_resolution': 'FwpmGetAppIdFromFileName0',
            'executable_name': ntpath.basename(exe),
            'executable_sha256': row['sha256'],
            'remote_ip': row['remote_ip'], 'remote_port': row['remote_port'], 'protocol': row['protocol'],
        })
    return {
        'mode': 'preview_only', 'enforcement_active': False,
        'rules_created': 0, 'traffic_blocked': False,
        'warning': 'WFP design ONLY. Windows runtime, isolation, precedence and rollback NOT implemented.',
        'operations': result,
    }
