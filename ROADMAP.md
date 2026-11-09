# Roadmap

**Princípio:** manter as capacidades autorizadas de IDEs e agentes, sem disponibilizar desnecessariamente credenciais ao modelo.

| Marco | Escopo | Estado |
| --- | --- | --- |
| v0.1 | MCP local, SSH com chave no ssh-agent, APIs autenticadas com keyring, filtros básicos, auditoria | Protótipo / testes unitários |
| v0.2 | Perfis por projeto, política explícita para saída de dados e aprovações, testes de integrações por IDE | Planejado |
| v0.3 | Network Guard: controle de saída dos processos e subprocessos, telemetria e validação de destinos | Planejado |
| v0.4 | Launcher com sandbox/identidade restrita e isolamento de arquivos e credenciais | Planejado |
| v1.0 | Avaliação de segurança independente, instalador, cobertura funcional por IDE, documentação operacional | Planejado |

## Critérios de aceite de segurança

- Testes que demonstrem que credenciais não são retornadas pelas ferramentas MCP;
- Não permitir bypass de caminhos nem de destinos fora das permissões;
- O modo de proteção ativa deve falhar fechado em operações gerenciadas;
- Logs sem segredos ou conteúdo integral;
- Regras e lacunas de cobertura documentadas;
- Testes de performance e de regressão para manter fluxos autorizados funcionando.

## Temas para colaboradores

Contribuições que melhorem o modelo de ameaças, mecanismos de isolamento, autorização, observabilidade e testes de segurança são especialmente bem-vindas.

## Revisão de segurança (novembro de 2026)

Veja [`docs/SECURITY-RESEARCH-2026-11-08.md`](docs/SECURITY-RESEARCH-2026-11-08.md) para matriz de ameaças, lacunas de cobertura e prioridades P0/P1/P2. A proteção do broker MCP **não** equivale à interceptação global do tráfego dos agentes.

## Network Guard — incremento experimental, sem bloqueio

Disponível para revisão: inventário local de conexões por PID e subprocessos, com IPs ocultos por padrão e **nenhuma alteração no firewall**. Isto não conclui a v0.3 nem cobre todas as rotas de tráfego das IDEs. Consulte [docs/NETWORK-GUARD-PHASE1.md](docs/NETWORK-GUARD-PHASE1.md).

## Network Guard — fase 2: política simulada

O comando `network-plan` compara amostras locais com regras estritas, apresenta `allow_candidate`, `block_candidate` ou `review`, e **não altera o tráfego**. A próxima etapa é desenvolver o backend WFP com identidade verificável do executável, isolamento de subprocessos e rollback testado. Veja [docs/NETWORK-GUARD-PHASE2.md](docs/NETWORK-GUARD-PHASE2.md).

## Network Guard — fase 3A

Protótipo WFP preview-only: política explicitamente restrita a executável, hash SHA-256, IP público único, porta e protocolo. **Nenhum filtro é aplicado**; fase 3B deverá construir backend nativo de sessão dinâmica, autorização explícita, rollback e testes Windows em VM. Consulte docs/NETWORK-GUARD-PHASE3-WFP-PREFLIGHT.md.

## Fase 3B — diagnóstico WFP nativo

O comando `wfp-native-diagnose` consulta a identidade do executável via `fwpuclnt.dll`, abrindo e encerrando uma sessão dinâmica vazia. **Ainda não há enforcement**, e o teste automatizado é simulado. Antes de adicionar filtros temporários, são obrigatórios testes reais no Windows, revisão de privilégio, escopo e rollback. [Plano da fase 3B](docs/NETWORK-GUARD-PHASE3B-NATIVE-DIAGNOSTICS.md).

## Fase 3C — WFP nativo, bloqueio de laboratório

Implementação experimental de um único filtro temporário WFP, somente via executável manual e confirmação dupla em VM descartável. Há testes Python simulados e compilação Windows em CI, mas falta testar comportamento real, compatibilidade, rollback e efeitos de filtros. **Não liberado em produção.** Consulte `docs/NETWORK-GUARD-PHASE3C-WFP-LAB.md`.

## Fase 3C — auditoria do ciclo de vida de filtros (para revisão)

Consulta somente leitura por ID WFP para evidenciar presença e desaparecimento de filtro após o fechamento da sessão ou interrupção do helper. A API de fechamento agora tem resultado verificado. **Ainda faltam ensaios funcionais reais em uma VM Windows isolada.**

## Fase 3E — revisão offline de evidências WFP

Ferramenta local e sem acesso à rede para análise de evidências manuais de filtros temporários, validação de remoção após encerramento normal e abrupto, e verificação de relatos de conectividade restaurada. Não executa WFP nem aprova uso em produção; validação em VM e revisão independente continuam obrigatórias.

## Fase 3F — ambiente experimental RFC1918

Helper WFP e planejador limitados a IPv4 privado RFC1918 (exige VM e rede isolada de verdade); cliente TCP dedicado para testar novas conexões sem transmitir conteúdo; CI apenas compila os executáveis. Preview público preservado como simulação. **Ainda não existe validação de bloqueio real em VM.**
