# Publicação inicial no GitHub

Conta prevista: `samirbridi`
Repositório proposto: `mizin-privacy-guard`
Visibilidade: `Public` (somente após revisão do código)
Branch padrão: `main`
Licença proposta: Apache-2.0

## 1. Crie o repositório vazio

Acesse https://github.com/new e configure:
- **Repository name:** `mizin-privacy-guard`
- **Description:** `Local-first security broker for AI coding agents | SSH, scoped APIs, MCP and secret protection`
- **Public**
- **NÃO** selecione README, .gitignore ou LICENSE no formulário (já estão neste pacote).

## 2. Faça o primeiro push (PowerShell)

Descompacte o pacote e abra o terminal dentro da pasta:

```powershell
git init -b main
git add .
git status
git commit -m "chore: initial open-source MVP v0.1"
git remote add origin https://github.com/samirbridi/mizin-privacy-guard.git
git push -u origin main
```

Antes de `git commit`, revise `git status` e o conteúdo de cada arquivo. Não inclua `.env`, `config.json` real, `audit.jsonl`, chaves, senhas ou logs.

Se o repositório já existir com commits, NÃO force push: faça backup e reconcilie os históricos antes de enviar.

## 3. Configure segurança e colaboração

- Settings → General → Features: habilite Issues e Discussions (se disponível).
- Settings → Branches / Rulesets: PR obrigatório para `main`, revisão do mantenedor, testes obrigatórios, impedir force-push.
- Settings → Security & analysis: habilite Dependabot, secret scanning e push protection (conforme disponibilidade do plano).
- Security → Advisories: habilite private vulnerability reporting (se disponível).
- Convide colaboradores somente com a permissão necessária; prefira PRs de forks para contribuições abertas.
- Revise a escolha da licença com seu objetivo de distribuição antes de publicar.
