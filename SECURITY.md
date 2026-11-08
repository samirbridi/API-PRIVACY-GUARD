# Política de Segurança / Security Policy

Este é um **protótipo experimental (v0.1)**. Não o utilize como único controle de segurança para credenciais de produção.

## Relatar vulnerabilidades / Reporting vulnerabilities

**Não abra uma issue pública** para falhas de segurança, tokens, chaves privadas, dados pessoais ou provas de conceito contendo acessos reais.

Use **GitHub → Security → Advisories → Report a vulnerability**, se a opção estiver disponível no repositório. Caso não esteja, solicite ao mantenedor um canal privado por uma issue genérica **sem detalhes da falha**.

Inclua, de forma sanitizada: impacto, versão, passos de reprodução com dados fictícios e sugestões de correção. Não realize testes em sistemas de terceiros sem autorização.

Não há programa de bug bounty nem promessa de prazo de resposta nesta versão.

## O que a v0.1 NÃO garante

- Não intercepta nem bloqueia requisições diretas de IDEs/agentes para seus modelos de IA.
- Não isola o MCP ou a IDE de outros processos executados com a mesma identidade do usuário.
- O `ssh-agent` protege a chave privada de exposição direta, mas não impede que um processo autorizado solicite assinaturas ao agente.
- O scanner de segredos baseado em expressões regulares pode ter falsos negativos e falsos positivos.
- Não inspeciona todos os **dados de saída** de requisições HTTP criadas pelo agente.
- Respostas de ferramentas MCP **podem ser enviadas ao fornecedor de IA** pela própria IDE.
- Tarefas SSH previamente autorizadas podem executar ações perigosas se forem cadastradas incorretamente.
- Não fornece suporte de autenticação por senha SSH, bloqueio global de rede, ou sandbox de processos.
- Não há testes end-to-end com provedores/IDEs reais neste pacote.

## Diretrizes para contribuições de segurança

1. Proponha mudanças pequenas, com testes automatizados reproduzíveis.
2. Negue operações em caso de falha de validação; não introduza bypass silencioso.
3. Evite logar dados pessoais, prompts completos, tokens e chaves.
4. Não acrescente certificados raiz globais, desative validação TLS ou SSH host-key checking.
5. Use apenas credenciais fictícias e servidores de testes.
6. Documente o modelo de ameaças e as limitações de cada mudança.

## Versões

| Versão | Status |
| --- | --- |
| 0.1.x | Experimental, sem garantia de uso em produção |
