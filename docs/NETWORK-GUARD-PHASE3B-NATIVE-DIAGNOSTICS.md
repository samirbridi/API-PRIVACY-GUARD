# Network Guard — Fase 3B: diagnóstico WFP nativo (sem enforcement)

**Estado:** implementação experimental para revisão. A Fase 3B começa por um diagnóstico nativo com `fwpuclnt.dll`, **não por bloqueio**.

## Problema que esta etapa resolve

As fases anteriores identificam conexões e validam propostas *offline*. Agora podemos verificar, em uma máquina Windows autorizada, se o próprio sistema consegue:

1. Abrir uma sessão WFP dinâmica via `FwpmEngineOpen0`;
2. Resolver a identidade WFP de um executável pelo `FwpmGetAppIdFromFileName0`;
3. Liberar a memória retornada com `FwpmFreeMemory0`;
4. Encerrar a sessão via `FwpmEngineClose0`;
5. Informar apenas metadados não confidenciais (SHA-256 do executável, comprimento e prefixo de hash do identificador de aplicativo).

O código **não importa nem chama `FwpmFilterAdd0`, `FwpmSubLayerAdd0`, `FwpmTransactionBegin0` ou APIs de alteração de regras**. É impossível ativar bloqueios por meio deste comando, mesmo executado com privilégios elevados. Ele tampouco altera o Windows Firewall, proxy, registro ou serviços.

## Uso em laboratório no Windows

Rode primeiro em ambiente de testes, sem informações confidenciais e preferencialmente em conta sem privilégios administrativos:

```powershell
.\.venv\Scripts\python.exe -m api_privacy_guard.cli wfp-native-diagnose --exe 'C:\Program Files\ExampleIDE\agent.exe'
```

Use o caminho real do `.exe`. O comando falha se não conseguir ler e identificar um executável ou abrir/fechar a sessão. Não solicita elevação UAC automaticamente.

Exemplo **fictício** da estrutura de saída:

```json
{
  "mode": "native_diagnostics_only",
  "session_dynamic": true,
  "session_closed": true,
  "firewall_modified": false,
  "filters_created": 0,
  "wfp_app_id_size": 96,
  "wfp_app_id_sha256_prefix": "e3b0c44298fc1c14",
  "executable_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

Os valores acima **não são um resultado observado**, apenas uma representação do formato.

## Requisitos para filtros temporários (próximo PR, após teste Windows)

- Confirmar em Windows 10/11 a assinatura/ABI das estruturas com testes integrados que façam `FwpmEngineOpen0` e `FwpmEngineClose0` reais.
- Criar **um sublayer próprio e dinâmico**, nunca filtros globais, permanentes ou de inicialização.
- Limitar condições de cada regra a executável autorizado (`FWPM_CONDITION_ALE_APP_ID`), IP único, protocolo e porta, nas camadas `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`.
- Exigir confirmação humana por sessão e usar VM com snapshot e console de recuperação, limites de tempo e rollback verificado.
- Encerrar a sessão automaticamente ao sair e por falha; validar erros de início/commit/abort, encerramento abrupto e o comportamento da BFE.
- Não confundir o hash SHA-256 de um executável em disco com a identidade imutável do processo em execução: atualizações, troca de arquivo e processos filhos exigem uma solução própria.
- Exercitar IPv4/IPv6, UDP/QUIC, DNS/DoH, proxy, VPN, Git, SSH, Windows Firewall, GPO/MDM e políticas conflitantes.
- O controle WFP atua sobre conexões, **não decodifica HTTPS nem promete impedir reutilização dos dados já recebidos por um servidor**.

## Restrições da fase atual

Não há evidência de comportamento correto em hardware Windows real; apenas testes automatizados com funções nativas simuladas foram feitos em ambiente isolado. A identidade WFP obtida pode conter informação local no blob; por isso **o conteúdo integral do identificador nunca é retornado**. O resumo com hash não garante anonimato em todas as circunstâncias.

## Fontes Microsoft

- [FwpmEngineOpen0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0)
- [FWPM_SESSION0 / FWPM_SESSION_FLAG_DYNAMIC](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0)
- [FwpmGetAppIdFromFileName0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0)
- [WFP Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)
