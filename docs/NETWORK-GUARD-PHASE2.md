# Network Guard — fase 2: políticas de saída (somente simulação)

Esta etapa compara conexões **já observadas** do processo escolhido e de seus subprocessos com regras locais. Não cria regras WFP, não intercepta pacotes, não muda o firewall e **não bloqueia nenhum tráfego**. A saída classifica conexões como `allow_candidate`, `block_candidate` ou `review`. São recomendações para análise, nunca decisões de enforcement.

## Exemplo (PowerShell, Windows)

No diretório do projeto:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[network,test]"
Get-Process | Where-Object { $_.ProcessName -match 'codex|trae|antigravity' } | Select-Object Id, ProcessName
.\.venv\Scripts\python.exe -m api_privacy_guard.cli network-plan --pid 1234 --policy examples/network-policy.example.json
```

Substitua o PID 1234 pelo ID real da IDE. Este comando não detecta ferramentas confiáveis automaticamente. `--no-children` limita a amostra ao processo principal. `--show-ip` exibe IPs somente no terminal local: não publique relatórios com endereços privados.

Por padrão a saída contém apenas nome do processo, PID, porta, protocolo, categoria do destino, regra correspondente e classificação, sem registrar conteúdo de pacotes, URLs, prompts, comandos, tokens ou chaves. A coleta de IPs exatos ocorre temporariamente na memória para comparar redes CIDR; os IPs são removidos da saída sem `--show-ip`. Nenhum dado é enviado pelo comando a serviços externos.

## Formato de políticas

```json
{
  "schema_version": 1,
  "default_action": "review",
  "rules": [
    {
      "id": "approved-ssh-lab",
      "action": "allow_candidate",
      "process_names": ["ssh.exe"],
      "protocols": ["tcp"],
      "remote_ports": [22],
      "remote_scopes": ["private_or_reserved"],
      "remote_cidrs": []
    }
  ]
}
```

Regras exigem processo, protocolo, porta e categoria/CIDR. `default_action` é **sempre** `review`; não existe permissão global automática. Para endereços, categorias e CIDRs são combinados por **OU**, enquanto os campos de processo/protocolo/porta precisam coincidir. CIDRs devem ser canônicos, por exemplo `10.0.0.0/8`. Quando várias regras coincidem, `block_candidate` prevalece sobre `review` e `allow_candidate` **somente na simulação**. O arquivo tem limite de 64 KiB e rejeita chaves duplicadas e campos desconhecidos.

**Atenção:** nomes de processos podem ser falsificados e não equivalem a identidades de aplicativos. Os resultados são snapshots parciais (possivelmente incompletos). Uma contagem zero **não significa ausência de vazamento**. Processos curtos, DNS delegado, VPN, proxy e tráfego de aplicativos externos à árvore podem não aparecer.

## Requisitos antes do bloqueio efetivo

1. Identificar o aplicativo no Windows pela identidade do executável, não apenas por nome/PID. A API WFP permite filtros por `FWPM_CONDITION_ALE_APP_ID` e usa `FwpmGetAppIdFromFileName0`.
2. Desenvolver backend próprio para as camadas `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`, com regras e precedência verificadas e nenhuma alteração indiscriminada da política global de firewall.
3. Implementar privilégio mínimo para configuração, rollback independente, limpeza de regras após falhas, testes de restauração, e autorização humana antes de qualquer bloqueio.
4. Cobrir IPv4/IPv6, subprocessos, DNS/DoH, UDP/QUIC, HTTP/2, WebSockets, SSH, proxy, VPN, loopback e conexões rápidas.
5. Preservar operações legítimas: SSH Agent, Git, deploys e acesso a APIs aprovadas; validar em Windows 10 e 11 em máquina de teste.
6. Combinar controle de rede com isolamento de credenciais e análise de conteúdo autorizada: WFP **não revela por si só o conteúdo HTTPS** enviado à API.

**Não criar uma regra global Block esperando que uma regra Allow convencional a sobreponha**: as regras do Windows Firewall possuem precedências específicas que podem cortar operações legítimas.

Referências oficiais:
- [Microsoft — Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [Microsoft — condições WFP por camada](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer)
- [Microsoft — FwpmGetAppIdFromFileName0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0)
- [Microsoft — New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)

**Status:** fase experimental, somente diagnóstico e planejamento. Não utilizar como prova de proteção global de dados.
