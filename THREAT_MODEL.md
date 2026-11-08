# Modelo de ameaças / Threat model

## Objetivo

Um agente de programação autorizado deve poder solicitar tarefas (ler arquivos remotos, editar código, acionar APIs) sem precisar receber a senha, o token ou o conteúdo da chave privada.

## Componentes e confiança

| Componente | Nível de confiança |
| --- | --- |
| Operador / configuração local revisada | Controle administrativo do MVP |
| Broker MCP e código de políticas | Confiável somente se isolado e íntegro |
| IDE / agente / plugins de terceiros | Potencialmente comprometidos |
| Respostas de servidores, arquivos e documentação lidos pelo agente | Dados não confiáveis |
| Provedor do modelo | Serviço externo, com políticas próprias |
| SSH Agent / Windows Credential Manager | Cofre do SO; escopo depende da identidade do processo |

## Ameaças abordadas parcialmente

- Exposição acidental de chaves privadas e tokens nas respostas do broker;
- Chamadas de APIs fora de perfis fixos e de métodos/caminhos autorizados;
- Leitura de caminhos SSH explicitamente proibidos;
- Registro acidental de segredos em logs do broker.

## Ameaças ainda sem mitigação completa

- Prompt injection em arquivos externos ou respostas que influencie o agente;
- Acesso direto do processo IDE à rede, ao sistema de arquivos ou ao cofre do usuário;
- Roubo de credenciais por malware na mesma conta Windows;
- Uso indevido de credenciais por aplicativos autorizados com acesso ao SSH Agent;
- Vazamento de dados que não correspondem aos padrões do scanner;
- Corridas de symlink e outras vulnerabilidades em operações remotas;
- Retenção dos dados de prompts/arquivos pelos fornecedores de modelos;
- Engenharia social ou políticas de exceção amplas demais.

**Importante:** MCP não é um sandbox. A confiança depende da separação efetiva de identidades, permissões e processos, planejada para fases posteriores.

## Filosofia

Negar por padrão aquilo que o broker não está autorizado a fazer, não capturar segredos em logs e manter a autenticação o mais próxima possível do executor local.
