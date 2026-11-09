# Network Guard — Fase 3C: filtro WFP temporário, SOMENTE EM VM

> Experimental. O helper pode bloquear uma conexão real. Use somente em VM Windows descartável com snapshot e console de recuperação, nunca num PC de trabalho. Não foi validado em Windows real.

## Implementado

O arquivo native/wfp_lab_block.cpp cria um único filtro WFP de ação BLOCK, restrito simultaneamente a:
- identidade WFP do executável (ALE_APP_ID);
- um IP IPv4 remoto privado RFC1918 (rede isolada, Fase 3F);
- uma porta remota;
- um protocolo TCP/UDP.

O helper utiliza sessão dinâmica (FWPM_SESSION_FLAG_DYNAMIC), subcamada própria e transação. O tempo máximo do filtro é 30 segundos; após encerrar a sessão, os objetos dinâmicos devem ser removidos pelo WFP. Isso ainda requer validação real.

Há confirmação dupla: argumento --confirm LAB-ONLY-EPHEMERAL-BLOCK e variável APG_WFP_DISPOSABLE_VM=I_ACCEPT_VM_ONLY_LAB. Nenhum instalador, MCP, agente ou workflow executa o helper.

## Compilação manual (VM, Windows SDK/MSVC)

Abrir x64 Native Tools Command Prompt for VS no diretório do projeto e executar:

    cl /nologo /std:c++17 /EHsc /W4 /utf-8 native\wfp_lab_block.cpp /Fe:wfp_lab_block.exe fwpuclnt.lib ws2_32.lib ole32.lib advapi32.lib

A GitHub Action desta etapa faz SOMENTE compilação; não executa binários nem altera o Windows Firewall.

## Planejamento sem instalar filtros

1. Criar uma cópia de examples/wfp-lab-private.example.json com uma regra, executável de TESTE, SHA-256, IP RFC1918 e porta explícitos. Mantenha mode=preview_only. **Não use IPs públicos em testes do helper.**
2. Somente na VM Windows, executar manualmente no PowerShell:

    .\.venv\Scripts\python.exe -m api_privacy_guard.cli wfp-lab-plan --proposal .\wfp-proposal.local.json --helper 'C:\Lab\APG\wfp_lab_block.exe' --seconds 10 --confirm-disposable-vm

O planejador apenas retorna parâmetros para revisão; não executa o helper. Somente um operador humano pode optar por executar manualmente o comando na VM, após conferir seu destino e a possibilidade de restauração.

## Lacunas e riscos

- O helper NÃO foi compilado/executado em Windows pela equipe; apenas testes locais simulados foram realizados.
- Somente IPv4, uma regra, TCP/UDP e IP explícito. Não cobre IPv6, DNS/DoH, VPN, proxy, QUIC, subprocessos ou bypass da IDE.
- O planejador e o helper nativo verificam SHA-256. O helper recebe `--sha256 <64 hex minúsculos>`, mantém um handle de leitura que nega compartilhamento de escrita/exclusão e compara o hash **antes** de abrir a sessão WFP. Isso reduz uma janela de substituição do arquivo, mas **não garante** identidade do processo em execução, nem elimina acessos preexistentes ou alterações no sistema com privilégios elevados. A identidade do filtro WFP continua baseada no App ID.
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

## Hardening da Fase 3D: SHA-256 obrigatório na execução nativa

O comando preparado em `wfp-lab-plan` inclui agora `--sha256 <hash-do-executável>`. O helper rejeita hash ausente, divergente ou inválido. Usa CryptoAPI/Windows para ler o arquivo, mantém um handle de leitura restrito durante a sessão e recusa pontos de redirecionamento detectados no caminho final. Não existe alteração automática no Windows e o helper continua limitado à VM descartável. O valor do hash pode revelar a versão do executável quando compartilhado; evite publicar dados identificáveis de instalações locais.

**Validação pendente:** build Windows CI e ensaios em VM. A verificação não associa criptograficamente o filtro WFP ao processo que já estiver rodando; não é atestado de assinatura, nem proteção contra administrador comprometido.

## Fase 3F — destino privado e cliente de laboratório

O helper foi restringido a redes privadas RFC1918; a validação do planejador aplica a mesma regra. A proposta pública `wfp-proposal.example.json` permanece exclusiva do comando `wfp-preview` (simulação) e **não é aceita pelo laboratório**. Consulte `docs/NETWORK-GUARD-PHASE3F-ISOLATED-TEST-NETWORK.md`.
