# Prompt mestre para integrar e evoluir API PRIVACY GUARD

Use este texto com a sua IDE de programação **após** abrir a pasta do repositório e revisar o conteúdo. Não forneça senhas/tokens no prompt.

---

Você atuará como engenheiro de segurança e software no projeto **API PRIVACY GUARD**.

## Meta principal

Permitir que os agentes de desenvolvimento continuem usando normalmente os acessos autorizados de cada projeto (SSH, leitura/edição remota, Git, deploy, APIs com autenticação), mas mantendo tokens, chaves e senhas em armazenamento local e impedindo que essas credenciais sejam passadas ao modelo ou expostas em logs e mensagens. Nem tudo que é lido pelo agente permanece local: conteúdo retornado ao contexto pode ir ao fornecedor do modelo. Deixe esta distinção visível e sob política explícita.

## Regras de implementação

1. Comece por executar os testes existentes. Faça inventário técnico e do comportamento das IDEs; não altere integrações ativas sem verificar compatibilidade.
2. Preserve o funcionamento dos projetos. Inicialmente execute apenas auditoria/monitoramento nas aplicações existentes; habilite bloqueio depois de testes e configuração por projeto.
3. Nunca exiba, copie para logs, ecoe, armazene em JSON ou envie em prompts valores de tokens/senhas/chaves. Use `ssh-agent`, cofre do Windows e credenciais de escopo mínimo. Não use tokens reais em testes.
4. Não prometa proteção global enquanto uma IDE possuir acesso a ferramentas de terminal/arquivos/rede fora do broker. Documente claramente lacunas e riscos.
5. Os executores devem verificar destino, operação, caminho, método, projeto e política **no código confiável**, não por instruções de prompt. Proíba execução arbitrária de shell sob o pretexto de segurança.
6. Use HTTPS validado, SSH com host key conhecida, conexões para destinos aprovados e registro de metadados sem corpo de requisições.
7. Evite dependências obscuras, certificados globais MITM, drivers de kernel e alterações de firewall do sistema nesta primeira etapa.
8. Faça testes unitários, de integração, adversariais e regressão. Em falhas de inspeção, bloqueie somente a operação gerenciada, preservando aplicativos externos.
9. Antes de iniciar uma alteração destrutiva ou com risco de indisponibilidade em servidor real, obtenha confirmação explícita do operador.
10. Use documentação oficial e verifique a versão das APIs de MCP e configurações reais das IDEs.

## Roadmap de evolução

- Confirmar interfaces MCP suportadas por cada IDE real.
- Adicionar suporte seguro à autenticação SSH por senha, caso necessário, sem expor senha ao agente.
- Adicionar criação de arquivo atômica, edição por diff, backup/rollback de escrita e aprovações de deploy.
- Adicionar observabilidade e logs locais com retenção limitada e ACLs.
- Adicionar verificação de saída sensível antes de dados serem fornecidos ao contexto do modelo.
- Criar proteção por processo e workspace, com isolamento real de credenciais e acesso à rede.
- Criar dashboard WPF e instalador assinável para Windows.

Entregue sempre: alterações de código, testes executados, riscos residuais e instruções de rollback. Nunca declare que um recurso está protegido sem um teste que demonstre o controle.
