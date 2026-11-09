# Network Guard — Fase 3E: revisão offline de evidências de teste WFP

**Avaliador somente leitura:** não chama WFP, não executa binários, não consulta rede, não inspeciona pacotes e não altera o firewall. Recebe um registro estruturado e manual do operador e identifica informações faltantes ou contraditórias.

## Uso local

    python -m api_privacy_guard.cli wfp-evidence-review --file .\wfp-evidence.local.json

Comece copiando examples/wfp-evidence.example.json e substitua as informações de exemplo pelas observações obtidas em uma VM Windows descartável. O exemplo é deliberadamente inconclusivo. NÃO compartilhe logs brutos, caminhos, credenciais, IPs ou informações do laboratório com um modelo de IA.

## Evidência mínima — execução normal

- Em uma VM isolada, use apenas programa de teste e endpoint sob controle do operador. Os testes de conexão precisam partir do MESMO executável configurado no filtro WFP, não do PowerShell, browser ou outro processo.
- Registre o ID exato que o helper imprimiu como APG_FILTER_ID=N.
- Faça uma consulta usando esse ID durante a janela do filtro (APG_FILTER_PRESENT=true) e outra após a sessão encerrar (APG_FILTER_PRESENT=false).
- Registre APG_SESSION_CLOSED=true e saída zero somente se ambos ocorrerem.
- Confirme com conexões NOVAS que o endpoint estava acessível antes, bloqueado durante e novamente acessível depois.

## Evidência adicional — interrupção abrupta

Realize um segundo ensaio, com novo ID de filtro, verificando presença durante o teste, ausência após encerrar abruptamente o processo e conectividade restaurada. A ferramenta offline nunca encerra processos nem executa esse ensaio.

## Como ler o relatório

- reported_checks_consistent = o relato do operador é internamente coerente, SEM prova independente de funcionamento real.
- incomplete_or_inconsistent = dados pendentes, erro de consulta, fechamento não confirmado, conectividade inconclusiva ou teste de falha ausente.
- ready_for_production = false SEMPRE, mesmo quando o relato é coerente.
- Erros APG_FILTER_QUERY_ERROR nunca são aceitos como prova da remoção de um filtro.

O registro usa valores enumerados e tamanho limitado (16 KiB), rejeita campos extras e chaves duplicadas e não reproduz IDs ou conteúdo original na saída. Os campos de contexto são declarações do operador, não detecção automática de virtualização. O ID de filtro não prova causalidade do bloqueio. Essa ferramenta não testa segurança dos provedores de IA, HTTPS ou a cobertura de tráfego fora da árvore do aplicativo.

Referências Microsoft:
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbyid0
- https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/tcp-ip-connectivity-issues-troubleshooting
