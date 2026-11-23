# API PRIVACY GUARD — MVP v0.1

**Executor local de acesso protegido para agentes de programação.** Primeira entrega: perfis SSH, requisições HTTPS autenticadas, cofre local de tokens, scanner simples de segredos, auditoria somente de metadados e integração MCP local via `stdio`.

> **Atenção:** protótipo experimental, não solução de proteção abrangente. Não bloqueia tráfego direto de Codex, TRAE ou Antigravity. Não garante que dados recebidos pelo modelo não sejam armazenados no servidor do fornecedor. Não instale a ferramenta com acesso administrativo ou credenciais de produção antes de revisar e testar o código.

## Como funciona

1. O agente chama uma ferramenta do servidor MCP local.
2. O guard consulta o perfil autorizado pelo usuário (`config.json`).
3. Para SSH, usa o OpenSSH / `ssh-agent` já configurado no computador. **Nunca retorna a chave privada ao modelo.**
4. Para API, busca um token no **Windows Credential Manager** usando `keyring`, acrescenta o cabeçalho de autenticação **localmente**, e envia a requisição HTTPS ao domínio cadastrado.
5. O conteúdo retornado passa por detector básico de segredos antes de aparecer no contexto do agente. Auditoria registra metadados, sem prompts, tokens ou arquivos.

**Distinção crucial:** os segredos podem permanecer locais, mas **o conteúdo de um arquivo remoto que a IA ler e analisar por essas ferramentas será enviado ao modelo de IA**, salvo bloqueio. Para eliminar esse envio seria necessário executar também o modelo localmente, ou limitar as operações a processamento local que devolva resultados não sensíveis.

## Instalação no Windows

Requisitos: Python 3.11 ou superior; OpenSSH Client instalado; `ssh-agent` configurado para destinos SSH; Windows 10/11. **Usar conta de usuário normal, não Administrador.** O script de instalação verifica Python 3.11+; não altera firewall ou configuração global.

No PowerShell, dentro da pasta descompactada:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m api_privacy_guard.cli init
.\.venv\Scripts\python.exe -m api_privacy_guard.cli status
.\.venv\Scripts\python.exe -m pytest -q
```

A configuração será criada em `%LOCALAPPDATA%\APIPrivacyGuard\config.json`.

**Por segurança, ambos os exemplos começam com `"enabled": false`.** Edite `config.json`, coloque seu host, usuário, diretório autorizado, comandos pré-cadastrados e defina `enabled: true` somente depois de confirmar que o perfil corresponde a um ambiente de testes.

### Configuração de SSH com chave local

No PowerShell (primeiro verifique com o administrador se o serviço já existe):

```powershell
Get-Service ssh-agent
ssh-add -l
ssh deploy@servidor-exemplo
```

Adicione sua chave ao agente se necessário, com `ssh-add $env:USERPROFILE\.ssh\id_ed25519`. Antes de permitir operações, conecte uma vez manualmente e verifique a impressão digital do host; o broker exige `StrictHostKeyChecking=yes` para rejeitar hosts SSH desconhecidos. Não use `StrictHostKeyChecking=no`.

O destino SSH precisa de `python3`. As ferramentas incluídas são:

- `ssh_read_file(target, absolute_path)`: retorna texto UTF-8 até o limite definido, após inspeção; bloqueia caminhos fora da raiz, segredos comuns e arquivos de credenciais.
- `ssh_write_existing_file(target, absolute_path, content)`: substitui o conteúdo de um arquivo **já existente**, dentro da raiz permitida. Não cria nem exclui arquivos. O executor remoto usa descritores de diretórios e `O_NOFOLLOW` para rejeitar links simbólicos (inclusive na raiz configurada e os internos) e hardlinks, evitando troca de alvos entre a validação e a abertura. Isso requer Python 3 em um servidor Unix/Linux.
- `ssh_run_registered_task(target, task_name)`: executa somente comandos pré-cadastrados em `tasks`; não aceita comandos arbitrários elaborados pelo modelo.

Para permitir uma nova tarefa SSH (por exemplo, reiniciar um serviço), acrescente manualmente uma entrada ao dicionário `tasks` do perfil. Essas tarefas são **comandos autorizados pela configuração**, portanto revise tudo que cadastrou; um comando mal configurado pode ler ou alterar outros caminhos.

### Configuração de API autenticada

No arquivo de configuração, atribua HTTPS, métodos e caminhos autorizados. Em seguida, grave o token sem passá-lo para o chat/IDE:

```powershell
.\.venv\Scripts\python.exe -m api_privacy_guard.cli secret-set demo-token
```

O programa pedirá o valor ocultamente. O alias `demo-token` corresponde ao campo `token_name` no perfil. O perfil suporta `auth: bearer` (cabeçalho `Authorization`) ou `auth: x-api-key`.

`call_authorized_api(service, method, relative_path, body_json)` não permite URL absoluta fornecida pelo modelo nem redirecionamentos HTTP. As permissões exigem método e caminho previamente cadastrados.

**Proteção de saída em desenvolvimento:** o broker local agora verifica padrões comuns de segredos em caminhos HTTP, parâmetros e JSON controlados pelo agente antes da transmissão. O token guardado localmente continua sendo inserido somente no cabeçalho HTTPS necessário ao destino previamente autorizado. Isto **não** intercepta chamadas diretas da IDE nem constitui um DLP completo. Veja [`docs/SECURITY-RESEARCH-2026-11-08.md`](docs/SECURITY-RESEARCH-2026-11-08.md).

### Vincular ao agente via MCP (stdio)

Consulte `examples/mcp-client-config.json`. Altere o caminho do Python para o absoluto da instalação. O comando é:

```powershell
C:\CAMINHO\API-PRIVACY-GUARD\.venv\Scripts\python.exe -m api_privacy_guard.mcp_server
```

**A configuração MCP varia por IDE e versão.** O arquivo JSON é um exemplo genérico, não garantia de integração com todas as IDEs. É preciso usar o menu/configuração de servidores MCP que cada ferramenta efetivamente disponibiliza.

### Atualização a partir de uma instalação anterior

**A renomeação alterou também o identificador MCP, o pacote Python, o diretório de configuração e o nome do serviço usado no cofre de credenciais.** Uma instalação anterior não é migrada automaticamente. Guarde um backup local de seus perfis (nunca no GitHub), atualize o caminho e o comando MCP nas IDEs e registre novamente os tokens pelo comando `secret-set`. Não cole senhas nem tokens no chat da IA.

## Network Guard (fase de inventário — somente leitura)

Um novo comando local observa conexões de uma IDE e dos seus subprocessos **sem bloquear a rede**:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[network,test]"
.\.venv\Scripts\python.exe -m api_privacy_guard.cli network-snapshot --pid 1234 --samples 5
```

Substitua 1234 pelo PID da IDE selecionada. A saída apresenta apenas metadados; endereços IP ficam ocultos por padrão (opção explícita --show-ip). O comando **não é um firewall nem comprova** que toda comunicação foi observada. Consulte [NETWORK-GUARD-PHASE1](docs/NETWORK-GUARD-PHASE1.md).

## Network Guard — simulação de políticas (fase 2)

Além de `network-snapshot`, o comando abaixo compara uma amostra de conexões locais com regras por processo, protocolo, porta e categoria/CIDR:

```powershell
.\.venv\Scripts\python.exe -m api_privacy_guard.cli network-plan --pid 1234 --policy examples/network-policy.example.json
```

As decisões `allow_candidate`, `block_candidate` e `review` são **apenas simulações**. O programa **não altera o firewall nem bloqueia conexões**; IPs ficam ocultos por padrão. Nomes de processos não são identidades confiáveis e snapshots não provam a ausência de vazamentos. Consulte [docs/NETWORK-GUARD-PHASE2.md](docs/NETWORK-GUARD-PHASE2.md).

## O que esta versão NÃO protege

- Chamadas diretas da IDE à API do modelo, browser incorporado, terminal próprio e outras ferramentas não mediadas pelo MCP.
- Acesso que o processo da IDE já tenha a arquivos locais, chave SSH, SSH Agent, cofre de credenciais ou rede. Para impedir esses acessos é necessário sandbox com identidade/ACL isoladas e políticas de rede, ainda não implementados.
- Todos os segredos possíveis: scanner por expressões regulares pode falhar (falsos negativos) e bloquear texto normal (falsos positivos).
- Dados pessoais em geral, arquivos grandes, arquivos binários, SSH para servidores Windows e credenciais armazenadas em extensões de terceiros.
- Proteção contra agente ou extensão maliciosa que já executa com as permissões do usuário Windows.
- Aprovação humana por operação, rollback de escrita, gateway HTTPS genérico, WFP/firewall, painel WPF, captura global, assinaturas e instalador: previstos para fases seguintes.

## Auditoria

`%LOCALAPPDATA%\APIPrivacyGuard\audit.jsonl` contém apenas data UTC, operação, alias de destino, decisão e um identificador truncado/hash do caminho. A auditoria não armazena corpo de requisições, texto remoto ou tokens. Proteger o acesso ao perfil do Windows continua necessário.

## Cenários de teste

Antes de qualquer uso real, utilize um servidor de testes com um usuário dedicado e sem permissões administrativas; teste leitura, escrita de arquivo temporário, arquivos de credenciais, travessia de diretórios, host SSH desconhecido, resposta com segredo e falha de rede. Só depois avalie integrar projetos reais.

## Fases seguintes

- v0.2: inspeção integrada de tráfego de IA e painel administrativo.
- v0.3: Network Guard por processo, política de rede e bloqueio de conexões diretas.
- v0.4: Launcher com conta/sandbox restrito, permissões de workspace e aprovação de operações sensíveis.
- v1.0: instalador Windows, instrumentação, suporte real por IDE, testes de segurança e atualização.

## Aviso

Este software foi gerado como protótipo inicial e testes unitários foram feitos em ambiente Linux isolado/mocks. **Não foi instalado nem testado nas suas IDEs ou servidores Windows/SSH reais.** Avalie cuidadosamente antes de conceder credenciais ou permissões de produção.

## Network Guard — fase 3A: pré-validação de filtros WFP

Os comandos `wfp-hash` e `wfp-preview --proposal` verificam executável Windows, SHA-256, destino, protocolo e porta antes de produzir um **plano não executável** para revisão. **Não são aplicadas regras WFP nem alterações de firewall**. Veja [a documentação da fase 3A](docs/NETWORK-GUARD-PHASE3-WFP-PREFLIGHT.md).

## Network Guard — Fase 3B: diagnóstico WFP nativo (experimental)

O comando `wfp-native-diagnose --exe 'C:\\Program Files\\ExampleIDE\\agent.exe'` realiza uma consulta local à Windows Filtering Platform (WFP): abre uma sessão dinâmica temporária, obtém o AppID do executável e fecha a sessão. **Não cria filtros, não bloqueia tráfego, não modifica o Firewall do Windows e não examina dados HTTPS.** Use inicialmente apenas em ambiente Windows de testes. Veja [a documentação de diagnóstico WFP](docs/NETWORK-GUARD-PHASE3B-NATIVE-DIAGNOSTICS.md).

### Fase 3C — Ensaio WFP temporário somente em VM

O projeto inclui um helper experimental C++ (`native/wfp_lab_block.cpp`) capaz de criar **um filtro de saída WFP** restrito a executável, IPv4, porta e TCP/UDP por até 30 segundos, utilizando sessão dinâmica. **NÃO é ativado automaticamente** por nenhuma IDE, MCP, instalador ou comando de diagnóstico. `wfp-lab-plan` apenas prepara um comando para revisão. O helper não foi validado em Windows real e **só deve ser compilado e testado manualmente em uma VM descartável**. Leia [`docs/NETWORK-GUARD-PHASE3C-WFP-LAB.md`](docs/NETWORK-GUARD-PHASE3C-WFP-LAB.md). Continua não sendo um firewall global de privacidade.

### Fase 3E — revisão offline de evidências de laboratório

Um novo comando local, wfp-evidence-review --file, avalia a coerência das observações de presença e remoção de filtro WFP e da recuperação de conectividade em ensaios de laboratório. **Não executa filtros, não inspeciona pacotes, não usa rede nem altera firewall.** Resultados coerentes não equivalem a comprovação independente ou autorização de produção. Veja docs/NETWORK-GUARD-PHASE3E-OFFLINE-EVIDENCE.md.

### Fase 3F — laboratório RFC1918 e cliente TCP de teste

O filtro WFP **manual** foi limitado a endereços IPv4 RFC1918, com uma proposta separada do preview público. Foi acrescentado um cliente TCP inofensivo que não envia conteúdo e pode medir novas tentativas de conexão com servidor próprio em rede host-only de VM. A compilação ocorre no CI, mas **nenhum executável é iniciado no runner**. Veja docs/NETWORK-GUARD-PHASE3F-ISOLATED-TEST-NETWORK.md.

### Network Guard — Fase 4A: Network Watch

O comando network-watch --pid 1234 --samples 5 --interval 1 [--policy examples/network-policy.example.json] compara destinos observados em múltiplas amostras. Os IPs são ocultos por padrão, e as classificações não bloqueiam conexões nem comprovam ausência de vazamentos. Veja docs/NETWORK-GUARD-PHASE4A-WATCH.md.
