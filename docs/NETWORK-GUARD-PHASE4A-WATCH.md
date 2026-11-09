# Network Guard — Fase 4A: observação multi-amostra (Network Watch)

Objetivo: identificar novos destinos observados entre várias amostras de sockets da IDE e dos subprocessos atuais. Este comando é LOCAL e SOMENTE LEITURA: não altera firewall, WFP, proxy, SSH, Git ou credenciais. Não captura pacotes, URLs, prompts, tokens ou conteúdo HTTP(S).

## Exemplo no Windows PowerShell

Instalar dependência opcional de rede: python -m pip install -e ".[network]"
Consultar processos: Get-Process | Where-Object { $_.ProcessName -match 'codex|trae|antigravity' } | Select-Object Id, ProcessName
Executar com PID selecionado: python -m api_privacy_guard.cli network-watch --pid 1234 --samples 5 --interval 1
Com classificação simulada: python -m api_privacy_guard.cli network-watch --pid 1234 --samples 5 --interval 1 --policy examples/network-policy.example.json

Os IPs são comparados apenas em memória e NÃO aparecem no relatório por padrão. Para diagnóstico privado, é possível acrescentar --show-ip; nunca publicar essa saída. O comando não inicia processos em segundo plano e não salva dados automaticamente.

## Limites

- Até 30 amostras; máximo de 3000 endpoints únicos e 100 alertas exibidos. Se um limite for atingido, incompletude será sinalizada.
- PID + horário de criação do processo raiz são verificados a cada amostra; isso não garante identidade dos processos filhos nem captura processos externos à árvore selecionada.
- Zero conexões encontradas não significa que nada saiu; conexões rápidas, DNS, proxy, VPN e permissão insuficiente podem produzir falsos negativos.
- Os alertas review e block_candidate representam somente recomendações de revisão de tráfego observado, nunca provas de atividade maliciosa ou instruções de bloqueio.
- A opção --policy é consultiva; sem política, todas as observações novas são review.

## Referências

- https://psutil.readthedocs.io/stable/
- https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-

Esta fase NÃO conclui a Issue #4 nem implementa controle de egresso real.
