"""Local MCP v2 stdio tools for user-approved SSH/API profiles.

IMPORTANT: MCP tool outputs are visible to the model. Credentials stay in the local
broker, but permitted remote file/API CONTENT may be shared with the model.
"""
from __future__ import annotations
from mcp.server import MCPServer
from .config import GuardError, load
from .sshbroker import run_ssh
from .apibroker import api_call

mcp = MCPServer("API Privacy Guard - local protected executor")


def report(call):
    try:
        return call()
    except GuardError as exc:
        return "BLOQUEADO: " + str(exc)
    except Exception:
        # Do not reveal subprocess stderr, request headers, traceback or credentials.
        return "ERRO: operação não concluída; consulte os logs locais de metadados."


@mcp.tool()
def list_authorized_targets() -> dict | str:
    """List authorized targets and pre-registered actions; no credentials returned."""
    def op():
        cfg = load()
        return {
            "ssh": {name: {"read": bool(p.get("read")), "write": bool(p.get("write")),
                           "tasks": list(p.get("tasks", {}).keys())}
                    for name, p in cfg["ssh_targets"].items() if p.get("enabled") is True},
            "apis": {name: {"methods": p.get("methods", []), "paths": p.get("allowed_paths", [])}
                     for name, p in cfg["api_services"].items() if p.get("enabled") is True},
        }
    return report(op)


@mcp.tool()
def ssh_read_file(target: str, absolute_path: str) -> str:
    """Read a permitted UTF-8 SSH file. CONTENT is returned to the AI; secrets detected by the scanner are blocked."""
    return report(lambda: run_ssh(load(), target, "read", path=absolute_path))


@mcp.tool()
def ssh_write_existing_file(target: str, absolute_path: str, content: str) -> str:
    """Update an EXISTING allowed remote UTF-8 file with full replacement contents. Does not reveal SSH key."""
    return report(lambda: run_ssh(load(), target, "write", path=absolute_path, data=content))


@mcp.tool()
def ssh_run_registered_task(target: str, task_name: str) -> str:
    """Run only a pre-registered SSH task (e.g. git status, restart). No arbitrary command text."""
    return report(lambda: run_ssh(load(), target, "task", task=task_name))


@mcp.tool()
def call_authorized_api(service: str, method: str, relative_path: str, body_json: str = "") -> str:
    """Call fixed HTTPS service/path with token fetched locally. Response BODY is returned to the AI after scanning."""
    return report(lambda: api_call(load(), service, method, relative_path, body_json))


if __name__ == "__main__":
    mcp.run(transport="stdio")
