# API PRIVACY GUARD — Experimental MVP 0.1

**Local-first access broker for AI coding agents.** Its goal is to keep SSH private keys and API tokens inside local OS facilities while allowing agents to request explicitly authorized operations through an MCP server.

## Safety status

This software is **experimental**. It is **not** a full sandbox, endpoint DLP, network firewall, or a guarantee against prompt/model data disclosure. The current agent process may still access OS resources directly.

- Python 3.11+, Model Context Protocol Python SDK v2
- SSH authentication through local OpenSSH/ssh-agent
- Scoped API tokens from Windows Credential Manager via `keyring`
- Configured destinations, file paths and predefined SSH tasks
- Limited secret patterns on responses returned to the model
- Metadata-only audit logs

**Do not use with production accounts, secrets, or hosts without independent code review.**

## Local development

```bash
python -m venv .venv
python -m pip install -e ".[test]"
python -m pytest -q
python -m api_privacy_guard.cli init
```

Both demo profiles start disabled. The MCP server is run with `python -m api_privacy_guard.mcp_server` after validating the IDE's MCP integration.

See [the Portuguese README](README.md), [security policy](SECURITY.md), [threat model](THREAT_MODEL.md), [roadmap](ROADMAP.md), and [contributing guide](CONTRIBUTING.md).

## Upgrading an earlier installation

The rename also changes the local configuration directory, keyring service, Python package and MCP server identifier. Previous profiles and tokens are **not automatically migrated**. Back up local policy files privately, update IDE MCP paths, and re-register tokens using the local CLI. Never paste secrets into your AI chat.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Network Guard — Phase 3A (read-only WFP preflight)

Windows CLI commands wfp-hash and wfp-preview verify a local executable fingerprint and a narrow, exact public-IP destination. This is a **design preview only**; no WFP session, firewall rule, or traffic blocking is activated. See [phase 3A documentation](docs/NETWORK-GUARD-PHASE3-WFP-PREFLIGHT.md).
