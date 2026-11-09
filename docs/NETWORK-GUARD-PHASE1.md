# Network Guard — fase 1: inventário local, sem bloqueio

Esta fase permite **observar conexões de rede** de um processo selecionado (por exemplo, a IDE) e seus processos filhos, usando psutil. **Não intercepta conteúdo, não bloqueia pacotes nem altera firewall, SSH ou proxy.**

## Instalação no Windows

No PowerShell, dentro do repositório:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[network,test]"
Get-Process | Where-Object { $_.ProcessName -match 'codex|trae|antigravity' } | Select-Object Id, ProcessName
.\.venv\Scripts\python.exe -m api_privacy_guard.cli network-snapshot --pid 1234 --samples 5 --interval 1
```

Substitua **1234** pelo PID real selecionado. O comando não identifica IDEs automaticamente nem pesquisa todos os processos do computador. Use --no-children para limitar a coleta à IDE principal.

Por padrão, a saída JSON permanece no terminal e **não contém IPs remotos exatos**: apresenta categoria de endereço, porta, protocolo, estado, PID e nome do processo. Nenhuma informação é enviada a serviços externos nem salva automaticamente. A opção explícita --show-ip inclui IPs para diagnóstico local, portanto evite compartilhá-los em relatórios públicos.

## Limitações de segurança

- Cada amostra mostra apenas conexões observáveis no momento. Conexões curtas podem passar despercebidas. **Zero conexões observadas não significa ausência de vazamento.**
- Processos podem terminar, ser criados fora da árvore da IDE ou ficar inacessíveis; permissões insuficientes podem limitar a coleta.
- O IP não identifica o domínio, URL, cabeçalhos, conteúdo, finalidade nem política de retenção do fornecedor.
- Não coleta comandos, arquivos, prompts, credenciais, cookies, conteúdo de pacotes, variáveis de ambiente ou corpo HTTP.
- Não aplica firewall, WFP, proxy, sandbox, bloqueio de saída nem monitoramento persistente em segundo plano.
- Não serve como evidência conclusiva de que dados não foram enviados.

## Próximas etapas para revisão da comunidade

1. Validar no Windows 10/11 com IDEs e subprocessos reais, IPv4/IPv6 e acessos negados.
2. Definir perfis de processo, destino e política sem alterar a rede existente.
3. Projetar mecanismo de egresso efetivo (WFP/firewall ou sandbox) com reversão e validação, sem interromper SSH ou APIs legítimas.
4. Isolar as credenciais da identidade do processo não confiável.
5. Criar testes adversariais para processos filhos, DNS, HTTP/2, WebSocket, QUIC e desvios de proxy.

## Fontes

- [Microsoft — Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection)
- [psutil — documentação de net_connections](https://psutil.readthedocs.io/stable/)
- [Microsoft — Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)

A primeira fase é **observacional**, não uma implementação completa de bloqueio.
