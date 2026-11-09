# Network Guard — Fase 3A (pré-validação WFP)

**Preview only:** nenhum filtro, serviço, firewall, proxy ou configuração do Windows é alterado.

A fase 2 classifica conexões observadas por **nome** de processo, que não é uma identidade confiável para enforcement. Esta etapa exige: caminho canônico absoluto do executável Windows, SHA-256 local correspondente, IP público único, porta remota e protocolo TCP/UDP. Proíbe wildcard, UNC, IP privado e regras globais.

## Windows PowerShell — somente leitura

    .\.venv\Scripts\python.exe -m api_privacy_guard.cli wfp-hash --exe 'C:\Program Files\ExampleIDE\agent.exe'

Copie o SHA calculado para uma cópia local de examples/wfp-proposal.example.json. O caminho e SHA no exemplo são fictícios.

    .\.venv\Scripts\python.exe -m api_privacy_guard.cli wfp-preview --proposal .\wfp-proposal.local.json

O resultado descreve condições futuras em FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6, baseadas em ALE_APP_ID, endereço, protocolo e porta. **Não é um filtro executável** e não há rollback porque nenhuma regra é aplicada.

## Próximo marco: WFP nativo, após revisão

- FwpmGetAppIdFromFileName0; sessão dinâmica FWPM_SESSION_FLAG_DYNAMIC para limpeza automática na interrupção; transações e reversão testadas.
- Aplicação exclusivamente em VM, com autorização humana explícita, escopo restrito e nenhum bloqueio global.
- Validar assinaturas e identidade de processo, filhos, DNS, IPv6, SSH, Git, HTTPS, VPN e CDNs; um IP pode hospedar muitos serviços.
- Testar precedência com Firewall/GPO/MDM antes de qualquer uso em produção.
- Não confundir bloqueio de conexão com inspeção de HTTPS nem com garantia contratual de não reutilização dos dados.

## Fontes oficiais Microsoft

- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
