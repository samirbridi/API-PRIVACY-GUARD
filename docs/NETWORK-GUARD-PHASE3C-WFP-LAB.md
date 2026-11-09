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
