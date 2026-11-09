# Security research — 2026-11-08

## Mission

API PRIVACY GUARD aims to prevent **unauthorized** sharing of credentials and confidential content while preserving authorized SSH, Git, agent and API workflows. An API receiving task data is not, by itself, evidence of improper retention or unauthorized reuse. Such claims require supplier-specific evidence and policies.

## Threat-surface assessment

| Surface | Potential leak | v0.1 status | Priority |
| --- | --- | --- | --- |
| Local MCP API broker | Secrets in model-controlled request URL, query and JSON | Outbound inspection proposed in this PR | P0 |
| MCP/SSH tool responses | Confidential file contents returned to model | Regex-based best-effort scanner | P1 |
| IDE → model API | Source code/prompts sent outside our broker | **Not intercepted** | P0 |
| Shell, browser, subprocesses | Alternative outbound network paths | **Not controlled** | P0 |
| Local credentials/SSH Agent | Compromised same-user process uses credentials | Credentials not returned by mediated tools; no OS isolation | P0 |
| Tool descriptions, remote README, web responses | Prompt injection / tool poisoning | No independent injection boundary | P1 |
| Provider-side storage after authorized transfer | Retention, reuse, sharing | **Not technically enforceable from local software** | Governance |

## What this change does

- Scans model-controlled API URL paths, query fields and normalized JSON bodies for common secret patterns.
- Compares against the *actual local authentication token* to stop accidental duplication into the URL/body, even if pattern recognition misses it.
- Checks several layers of percent encoding and refuses suspicious requests **before opening the HTTP transport**.
- Preserves normal authenticated requests: broker inserts the token in the HTTPS authentication header for an explicitly configured destination.
- Writes no secret or request body to audit logs. Adds regression tests for blocked and allowed requests.

This is an experimental, **best-effort** control with possible false positives and false negatives. It does **not** implement full DLP, arbitrary encoding detection, a generic HTTPS intercepting proxy, or global IDE coverage. Neither does it prove anything about the API supplier's intentions.

## Proposed next milestones

1. **P0 Egress map** — inventory and test real IDE, model, MCP, shell, browser, plugin and child-process network paths. Document actual interception coverage.
2. **P0 Boundary enforcement** — make protected execution run with separate OS identities/sandbox and narrow egress permissions. Audit all bypasses.
3. **P1 Approval engine** — define per-project/per-destination grants, data classifications, scoped expiration and revocation.
4. **P1 Content classifier** — add privacy-aware prompt/file classifications, redaction and intentional approvals before transmission.
5. **P1 Security harness** — add prompt-injection, SSRF, encoding, symlink, network failure, streaming, and token-misuse tests.
6. **P2 Compatibility matrix** — verify Windows 10/11 and specific Codex/TRAE/Antigravity versions with tests, not assumptions.

## References

- OWASP GenAI LLM Top 10 (2026): https://github.com/GenAI-Security-Project/GenAI-LLM-Top10
- OWASP MCP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- MCP Security Best Practices: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx
- Codex security cookbook: https://learn.chatgpt.com/docs/enterprise/security-cookbook
- GitHub Actions security: https://docs.github.com/en/actions/reference/security/secure-use
