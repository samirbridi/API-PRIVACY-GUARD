# Revisão de segurança — 09/11/2026

## Prioridades e evidências

- **P0 — SSH remoto:** a implementação anterior usava `realpath`/`isfile` e só depois abria o arquivo, permitindo uma janela TOCTOU. Este PR propõe abrir componentes de diretório por `dir_fd` e `O_NOFOLLOW`, impedindo symlinks na raiz configurada, nos intermediários ou no destino, além de rejeitar arquivos com múltiplos hardlinks e arquivos não regulares. Testes locais simulam o script que será executado via SSH; **testes com host SSH real ainda são necessários**.
- **P0 — Egress de IDEs:** a biblioteca MCP **não** intercepta requisições diretas de Codex, TRAE, Antigravity, PowerShell, Git e subprocessos; ver issue #4. Exigir controle real de rede/identidade antes de anunciar proteção global.
- **P0 — Saída de dados do broker API:** o PR #3 aborda padrões de segredos em queries e corpos JSON. Ele continua pendente de revisão; esta alteração SSH é independente.
- **P1 — Prompt injection e tool poisoning:** metadados de ferramentas, arquivos de repositório e conteúdos recebidos são entradas não confiáveis. Revisar aprovação e vinculação por projeto/destino sem confiar no conteúdo textual do modelo; ver issue #6.
- **P1 — Credenciais OAuth de MCP:** a especificação recomenda validação de audience e rejeição de token passthrough. Nosso MCP é local via stdio; essa recomendação aplica-se a futuras integrações MCP remotas com autenticação, não significa CVE nesta biblioteca.
- **P1 — Supply chain:** Dependabot propôs atualização dos GitHub Actions `checkout` e `setup-python` (PRs #1 e #2). Verificar CI e compatibilidade antes de integrar.

## Compatibilidade e limitações deste PR

- Continua possível ler e modificar arquivos regulares existentes em subpastas autorizadas com SSH Agent; comandos SSH cadastrados permanecem inalterados.
- **Mudança intencional:** symlinks, mesmo apontando dentro da raiz, e arquivos com mais de um hardlink serão recusados.
- `O_NOFOLLOW`, `O_DIRECTORY`, `dir_fd` e operações do script foram projetados para **Unix/Linux com Python 3** no destino. Não é uma implementação para servidor Windows remoto.
- A escrita por truncamento do arquivo existente **não é transacional/atômica**: interrupções podem deixar escrita parcial. Planejar backup/replace atômico em etapa separada.
- O perfil SSH e os limites de pasta continuam sendo responsabilidade do administrador. Este controle não impede que outros processos do usuário remoto editem arquivos ou alterem permissões.
- Não altera regras do Windows, tokens, chaves ou configurações de produção.

## Fontes oficiais consultadas

- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [OWASP AI Agent and MCP Security Guideline](https://owasp.github.io/DevSecOpsGuideline/2-Process/2-2-Develop/2-2-5-AI-Agent-and-MCP-Security/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Python os.open](https://docs.python.org/3/library/os.html#os.open)
