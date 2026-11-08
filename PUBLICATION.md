# Repositório e colaboração no GitHub

Repositório oficial: **[samirbridi/API-PRIVACY-GUARD](https://github.com/samirbridi/API-PRIVACY-GUARD)**  
Branch principal: `main`  
Licença: Apache-2.0  
Situação: protótipo experimental v0.1; **não usar como único mecanismo de proteção de dados**.

## Trabalhar com o projeto

```powershell
git clone https://github.com/samirbridi/API-PRIVACY-GUARD.git
cd API-PRIVACY-GUARD
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q
```

As ferramentas MCP usam `python -m api_privacy_guard.mcp_server`. Consulte [README.md](README.md) e [SECURITY.md](SECURITY.md) antes de conceder permissões.

## Contribuir

1. Faça fork, trabalhe em branch própria e abra um Pull Request.
2. Descreva testes, riscos e limitações observadas. Não inclua tokens, credenciais, hosts privados ou logs reais.
3. Para falhas de segurança, **não abra Issue pública**. Use o fluxo descrito em [SECURITY.md](SECURITY.md).
4. Antes de aceitar PRs, é recomendável proteger `main` com revisão e verificações automáticas.

## Recomendações aos mantenedores

- Settings → General: habilitar Issues/Discussions, conforme interesse.
- Settings → Branches/Rulesets: exigir PR, revisão de código e verificações de CI; impedir force-push.
- Settings → Security: avaliar secret scanning, push protection, Dependabot e private vulnerability reporting.
- Criar perfis de acesso de escopo mínimo para colaboradores e serviços automatizados.
