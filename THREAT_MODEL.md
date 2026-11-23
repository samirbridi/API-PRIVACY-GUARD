# Modelo de ameaças / Threat model

## Objetivo

Um agente de programação autorizado deve poder solicitar tarefas (ler arquivos remotos, editar código, acionar APIs) sem precisar receber a senha, o token ou o conteúdo da chave privada.

## Componentes e confiança

| Componente | Nível de confiança |
| --- | --- |
| Operador / configuração local revisada | Controle administrativo do MVP |
| Broker MCP e código de políticas | Confiável somente se isolado e íntegro |
| IDE / agente / plugins de terceiros | Potencialmente comprometidos |
| Respostas de servidores, arquivos e documentação lidos pelo agente | Dados não confiáveis |
| Provedor do modelo | Serviço externo, com políticas próprias |
| SSH Agent / Windows Credential Manager | Cofre do SO; escopo depende da identidade do processo |

## Ameaças abordadas parcialmente

- Exposição acidental de chaves privadas e tokens nas respostas do broker;
- Chamadas de APIs fora de perfis fixos e de métodos/caminhos autorizados;
- Leitura de caminhos SSH explicitamente proibidos;
- Registro acidental de segredos em logs do broker.

## Ameaças ainda sem mitigação completa

- Prompt injection em arquivos externos ou respostas que influencie o agente;
- Acesso direto do processo IDE à rede, ao sistema de arquivos ou ao cofre do usuário;
- Roubo de credenciais por malware na mesma conta Windows;
- Uso indevido de credenciais por aplicativos autorizados com acesso ao SSH Agent;
- Vazamento de dados que não correspondem aos padrões do scanner;
- Symlink/TOCTOU no acesso direto a arquivos SSH: mitigação proposta por `dir_fd`/`O_NOFOLLOW`, pendente revisão e testes com servidor real; outras corridas e limitações do SO permanecem;
- Retenção dos dados de prompts/arquivos pelos fornecedores de modelos;
- Engenharia social ou políticas de exceção amplas demais.

**Importante:** MCP não é um sandbox. A confiança depende da separação efetiva de identidades, permissões e processos, planejada para fases posteriores.

## Filosofia

Negar por padrão aquilo que o broker não está autorizado a fazer, não capturar segredos em logs e manter a autenticação o mais próxima possível do executor local.

## Inspeção de dados de saída (experimental)

O broker de APIs passa a inspecionar dados controlados pelo agente no caminho, query e corpo JSON **antes** da transmissão. Isso não substitui isolamento de processos nem cobre conexões diretas fora do broker. Veja `docs/SECURITY-RESEARCH-2026-11-08.md`.

## Inventário de rede (fase experimental)

O comando network-snapshot observa **parte** das conexões do processo/árvore selecionada. Não controla saída nem detecta necessariamente processos fora da árvore, conexões transitórias, DNS delegado ou conteúdos de tráfego criptografado. Zero conexões observadas **não** comprova ausência de vazamentos. Não há mudança no firewall nesta fase.

## Simulação de regras de saída

A fase 2 apenas interpreta snapshots locais. Nomes e PIDs de processos podem ser contornados, dados de amostragem podem estar incompletos e não há intervenção em conexões HTTPS. Por isso não reivindicamos filtragem global de dados nem isolamento de agentes. Identidade por executável, política WFP, rollback, supervisão e proteção de conteúdo continuam pendentes. Veja `docs/NETWORK-GUARD-PHASE2.md`.

## WFP preflight (fase 3A)

Identidade por caminho e hash é verificada apenas no instante da proposta, não vincula de forma imutável o processo e não bloqueia subprocessos ou conexões. IPs podem representar serviços compartilhados. O preflight não intercepta dados HTTPS nem altera a rede. Nenhuma garantia de enforcement é feita nesta fase.

## Limite do diagnóstico WFP nativo — Fase 3B

O diagnóstico WFP consulta a identidade nativa de um executável em uma sessão dinâmica temporária. O AppID integral não é retornado e nenhuma operação de criação de filtros é disponibilizada. **Essa consulta não impede vazamentos.** O futuro controle de saída exigirá filtros por executável/IPv4/IPv6, testes de precedência, isolamento de subprocessos e validação de rollback em Windows reais.

## Fase 3C — risco operacional em filtro WFP de laboratório

O helper nativo agora contém um filtro WFP real, mas é manual e exige confirmação dupla. Ele pode interromper tráfego que coincida com o escopo exato; a limpeza depende do encerramento da sessão dinâmica e deve ser verificada em VM. O SHA-256 é conferido novamente pelo helper nativo antes da adição do filtro, mas não equivale à identidade imutável do processo. Não existe isolamento de subprocessos nem inspeção HTTPS. **Não executar em produção ou em estações de transmissão.**

## Risco residual na verificação de rollback WFP

O novo probe permite diferenciar a ausência de um objeto de filtro de erro de consulta WFP. Isso não comprova efeitos reais da filtragem ou cobertura de processos filhos, VPN, IPv6 e tráfego HTTPS. A confirmação de VM é declarativa, não uma verificação de isolamento. Teste vivo segue pendente.

## Fase 3D — verificação nativa SHA-256 do alvo

O helper de laboratório agora exige um hash SHA-256 explícito e recalcula o digest local do executável antes de instalar o filtro, conservando o handle aberto com compartilhamento restrito. Isso reduz o risco de troca entre planejamento e execução, mas não fornece prova imutável de identidade do processo, não impede alterações por identidades privilegiadas nem cria um firewall abrangente. A execução permanece manual e confinada a VM de laboratório.

## Fase 3E — evidência offline não é atestado

Análise apenas de registros estruturados preenchidos manualmente pelo operador. Consistência entre eventos declarados não comprova que uma política WFP bloqueou pacotes, nem garante privacidade diante de APIs externas. Nenhum acesso à rede ou modificação de firewall acontece durante a avaliação.

## Fase 3F — isolamento de laboratório não é comprovado pelo IP

O helper passou a recusar endereços públicos e aceitar somente IPv4 RFC1918, minimizando testes contra terceiros. A faixa privada não comprova a virtualização ou isolamento da rede; o operador precisa controlar VM, adaptadores e servidor de teste. O cliente TCP não envia dados de aplicação, mas realiza handshake de rede quando executado manualmente. Falha de conexão isolada não prova que WFP a bloqueou.

## Fase 4A — limites do Network Watch

Amostragem de sockets visíveis de PID e descendentes, com IPs retidos somente em memória e ocultos da saída por padrão. Conexões fugazes, tráfego delegado, processos fora da árvore, DNS/DoH, VPNs, proxies e permissões do sistema podem escapar. A verificação PID+instante de criação reduz uma confusão sobre a identidade da raiz, mas não oferece identidade imutável para filhos. Não é DLP nem prova de tráfego ausente.
