# Network Guard — Fase 3F: ensaio WFP em rede privada de laboratório

**Status:** preparado para revisão. O código compila no GitHub Actions, mas os binários NÃO são executados pelo CI. Nenhuma validação WFP real ocorreu nesta entrega.

## Por que mudar

O helper anterior exigia IP público; isso tornava os testes de bloqueio dependentes de endpoints externos e contrariava o objetivo de um laboratório isolado. Esta etapa restringe o helper WFP e seu planejador a **endereços IPv4 RFC1918 específicos**. O preview geral ainda aceita IP público, mas não executa filtros.

## Topologia recomendada, exclusivamente em máquinas virtuais descartáveis

VM A: Windows 10/11, com WFP helper, probe, cliente dedicado e console local de recuperação.
VM B: servidor de laboratório operado pelo usuário na mesma rede **host-only**, com IP fictício de exemplo `192.168.56.20` e porta `48080`, sem acesso necessário à Internet.

Use IPs reais da sua rede virtual privada, não copie cegamente o exemplo. A faixa RFC1918 **não prova** que a rede é isolada; verifique a configuração dos adaptadores, desligue bridging e confirme que o destino pertence ao laboratório.

### Preparação (sem aplicar bloqueios)

Na VM B, inicie um listener TCP inofensivo na porta combinada. Uma opção, se Python estiver instalado na VM B, é executar `python -m http.server 48080 --bind 192.168.56.20`, somente na rede interna de testes. Não disponibilize pastas sensíveis nesse servidor: use um diretório vazio.

Na VM A, compile com o Windows SDK/MSVC:

    cl /nologo /std:c++17 /EHsc /W4 /utf-8 native\wfp_lab_connect.cpp /Fe:wfp_lab_connect.exe ws2_32.lib

Confira que o destino responde com uma tentativa de conexão que **não envia conteúdo**:

    .\wfp_lab_connect.exe --ip 192.168.56.20 --port 48080

O programa retorna `APG_TEST_CONNECT=reachable` ou `APG_TEST_CONNECT=unreachable`. **Unreachable NÃO significa que o WFP bloqueou**: erros da rede, do servidor e do Firewall do Windows têm resultado semelhante.

### Planejamento de teste controlado

1. Calcule o SHA-256 de `wfp_lab_connect.exe` usando `wfp-hash` e coloque o caminho completo e SHA correto em uma cópia local de `examples/wfp-lab-private.example.json`.
2. O comando `wfp-lab-plan` aceitará apenas um destino privado RFC1918, uma porta, TCP/UDP, um único executável `.exe`, hash aprovado e 5–30 segundos.
3. **Somente após confirmar snapshot da VM, console fora da rede e regras corretas**, o operador poderá compilar/executar o helper manualmente na VM. Não existem execução automática ou testes de integração em CI.
4. Repita o cliente manualmente antes, durante e depois de o filtro existir. Realize **novas conexões** para cada fase. O esperado é reachable / unreachable / reachable, mas isso precisa ser correlacionado com o filtro realmente presente pelo `wfp_lab_probe.exe`.
5. No ensaio adicional, interrompa o helper de forma controlada numa VM descartável e verifique ausência do filtro e conectividade restaurada. Não use a máquina principal para reproduzir falhas.
6. Anote as evidências como relatório local em `wfp-evidence-review`. O avaliador apenas verifica consistência; não comprova independentemente o bloqueio.

## Restrições e risco residual

- A proteção não cobre IPv6, DNS/DoH, VPN, proxies ou subprocessos.
- TCP e UDP são suportados pelo **helper**, mas o cliente dedicado desta fase exercita somente TCP.
- IP privado não significa autorizado: o operador precisa comprovar o isolamento real da VM e a titularidade do servidor.
- O WFP atua em autorização de fluxos; conexões existentes podem permanecer ativas. O helper não captura nem decodifica HTTPS. Nenhuma inferência de coleta indevida por provedores é possível apenas com esse ensaio.
- O helper tem capacidade de bloquear conexões quando executado manualmente; não use em computador de trabalho ou transmissão.

Fontes Microsoft:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
