# Como contribuir / Contributing

Obrigado por ajudar a fortalecer o **MIZIN PRIVACY GUARD**.

## Desenvolvimento

1. Faça um fork e crie uma branch a partir de `main`.
2. Instale o Python 3.11+ e execute:
   ```bash
   python -m venv .venv
   python -m pip install -e ".[test]"
   python -m pytest -q
   ```
3. Crie testes que falhem antes da correção e passem depois dela.
4. Abra um Pull Request com contexto, riscos, testes e eventuais mudanças na política.
5. Não inclua segredos, dados de clientes, IPs privados reais ou nomes de servidores de produção.
6. Para vulnerabilidades, siga **SECURITY.md** e não publique detalhes antes da correção coordenada.

### Áreas prioritárias

- Integrações MCP verificadas nas IDEs.
- Isolamento real de processos e workspaces no Windows.
- Controle de acesso de mínimo privilégio para SSH/API.
- Inspeção de conteúdo retornado ao modelo (incluindo formatos e codificações variadas).
- Auditoria privativa e explicável, aprovações e testes adversariais.
- Testes end-to-end em ambientes descartáveis.

### Política de revisão

Mudanças com impacto em autenticação, SSH, rede, processamento de segredos ou permissões precisam de revisão explícita do mantenedor. CI verde não equivale à garantia de segurança.

### Licença

Ao contribuir, você concorda que sua contribuição seja distribuída sob a licença Apache-2.0 do projeto, e declara ter direito de compartilhar esse código.
