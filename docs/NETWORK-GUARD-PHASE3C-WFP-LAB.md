# Network Guard — Fase 3C: filtro WFP temporário, SOMENTE EM VM

> Experimental. O helper pode bloquear uma conexão real. Use somente em VM Windows descartável com snapshot e console de recuperação, nunca num PC de trabalho. Não foi validado em Windows real.

## Implementado

O arquivo native/wfp_lab_block.cpp cria um único filtro WFP de ação BLOCK, restrito simultaneamente a:
- identidade WFP do executável (ALE_APP_ID);
- um IP IPv4 remoto global;
- uma porta remota;
- um protocolo TCP/UDP.

O helper utiliza sessão dinâmica (FWPM_SESSION_FLAG_DYNAMIC), subcamada própria e transação. O tempo máximo do filtro é 30 segundos; após encerrar a sessão, os objetos dinâmicos devem ser removidos pelo WFP. Isso ainda requer validação real.

Há confirmação dupla: argumento --confirm LAB-ONLY-EPHEMERAL-BLOCK e variável APG_WFP_DISPOSABLE_VM=I_ACCEPT_VM_ONLY_LAB. Nenhum instalador, MCP, agente ou workflow executa o helper.

## Compilação manual (VM, Windows SDK/MSVC)

Abrir x64 Native Tools Command Prompt for VS no diretório do projeto e executar:

    cl /nologo /std:c++17 /EHsc /W4 /utf-8 native\wfp_lab_block.cpp /Fe:wfp_lab_block.exe fwpuclnt.lib ws2_32.lib ole32.lib

A GitHub Action desta etapa faz SOMENTE compilação; não executa binários nem altera o Windows Firewall.

## Planejamento sem instalar filtros

1. Criar uma cópia de examples/wfp-proposal.example.json com uma regra, executável de TESTE, SHA-256, IP e porta explícitos. Mantenha mode=preview_only.
2. Somente na VM Windows, executar manualmente no PowerShell:

    .\.venv\Scripts\python.exe -m api_privacy_guard.cli wfp-lab-plan --proposal .\wfp-proposal.local.json --helper 'C:\Lab\APG\wfp_lab_block.exe' --seconds 10 --confirm-disposable-vm

O planejador apenas retorna parâmetros para revisão; não executa o helper. Somente um operador humano pode optar por executar manualmente o comando na VM, após conferir seu destino e a possibilidade de restauração.

## Lacunas e riscos

- O helper NÃO foi compilado/executado em Windows pela equipe; apenas testes locais simulados foram realizados.
- Somente IPv4, uma regra, TCP/UDP e IP explícito. Não cobre IPv6, DNS/DoH, VPN, proxy, QUIC, subprocessos ou bypass da IDE.
- A conferência SHA-256 ocorre na etapa de planejamento. O helper nativo não verifica o hash novamente; o WFP filtra por App ID, não por hash. Permanecem riscos de troca do executável e de identidade de processo.
- Bloqueios WFP podem entrar em conflito com firewall, GPO e MDM. Testar sempre SSH, Git e API em ambiente descartável.
- WFP não inspeciona HTTPS nem impede retenção posterior de dados que já chegaram a um fornecedor.

## Referências Microsoft

- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0

## Validação de vida útil e remoção do filtro (PR #12, revisão)

A versão experimental agora reporta `APG_FILTER_ID=<numero>` após criar e confirmar o filtro e `APG_SESSION_CLOSED=true` apenas quando a API `FwpmEngineClose0` confirma encerramento.

Uma ferramenta nativa separada, `native/wfp_lab_probe.cpp`, **somente consulta** o WFP por ID; não adiciona, remove nem altera filtros.

Compilar em uma VM Windows descartável, usando x64 Native Tools Command Prompt:

    cl /nologo /std:c++17 /EHsc /W4 /utf-8 native\wfp_lab_probe.cpp /Fe:wfp_lab_probe.exe fwpuclnt.lib

Durante o período de 5–30 segundos do filtro, anotar o ID mostrado pelo helper; em outro terminal da VM, executar:

    wfp_lab_probe.exe --filter-id <ID_DO_FILTRO>

O comando deve retornar `APG_FILTER_PRESENT=true` enquanto a regra existir. Depois de o helper encerrar a sessão, deve retornar `APG_FILTER_PRESENT=false`. Qualquer `APG_FILTER_QUERY_ERROR` é falha de consulta, e **nunca** prova de reversão. Repetir um ensaio com encerramento abrupto do helper e verificar a remoção usando o mesmo ID.

Executar testes funcionais de conexão **somente com cliente e endpoint controlados pelo operador, em VM e rede isolada**, antes/durante/depois do bloqueio. O probe confirma somente existência do filtro no WFP: não comprova que pacotes foram efetivamente bloqueados ou que não houve outros efeitos na rede.

A variável de confirmação declarada pelo operador não é uma prova técnica de que o Windows está em uma VM. Não executar em estação de produção ou transmissão, nem usar IPs de terceiros como alvos de testes.

Referências oficiais: [Microsoft FwpmFilterGetById0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbyid0), [Microsoft FwpmEngineClose0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineclose0), [WFP Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management).
