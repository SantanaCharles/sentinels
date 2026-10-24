# Política de segurança

## Reportar uma vulnerabilidade no Sentinels

Não abra issue pública. Use o **Private vulnerability reporting** do GitHub (aba *Security* →
*Report a vulnerability*) ou escreva para o e-mail de contato da Smart Code Tecnologia em
https://smartcodetecnologia.com.br.

Inclua versão (`sentinels version`), forma de instalação (systemd ou Docker) e passos para
reproduzir. Respondemos em até 5 dias úteis e combinamos a divulgação após a correção.

## Versões suportadas

Apenas a versão mais recente recebe correções de segurança.

## Garantias de projeto

- O agente é **somente leitura**: não altera containers, arquivos do sistema nem regras de
  firewall. Na instalação via Docker ele fala com a API do Docker por um proxy que bloqueia
  qualquer escrita.
- O **feed de alertas emergenciais** é assinado com Ed25519; o binário rejeita feed sem
  assinatura válida e o feed só pode acrescentar alertas, nunca remover os embutidos.
- Releases trazem `checksums.txt` (SHA-256); o `install.sh` recusa arquivo que não confere.
- Texto vindo de logs é tratado como dado não confiável em alertas, relatórios, notas do cofre
  e prompts de IA. A IA não executa ações.
- Segredos só via variáveis de ambiente; valores de variáveis dos containers não são lidos.

## Chave de assinatura do feed

A chave privada fica com os mantenedores, fora do repositório. Se for comprometida: gere um novo
par (`go run ./cmd/feedsign keygen`), atualize `FeedPublicKey` em `internal/intel/signing.go`,
assine o feed novamente e publique uma release — agentes antigos passam a rejeitar o feed e
seguem com a lista embutida até serem atualizados.
