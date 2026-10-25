# Operação: verificar, atualizar, testar e resolver problemas

Comandos para a instalação via **Docker Compose** (rode dentro da pasta `~/sentinels/deploy`).
No **systemd**, troque `docker compose exec sentinels sentinels …` por `sudo -u sentinels sentinels … -config /etc/sentinels/sentinels.yaml`
e `docker compose up -d --force-recreate sentinels` por `sudo systemctl restart sentinels`.

## 1. Está funcionando?

```bash
cd ~/sentinels/deploy
docker compose ps                                   # sentinels e socket-proxy "Up" (não "Restarting")
docker compose exec sentinels sentinels version
docker compose exec sentinels sentinels doctor -config /etc/sentinels/sentinels.yaml
docker compose exec sentinels sentinels notify-test -config /etc/sentinels/sentinels.yaml
docker compose logs --tail 40 sentinels
```

No log, procure:

| Linha | Significa |
|-------|-----------|
| `lendo containers em tcp://127.0.0.1:2375` | usando o proxy somente leitura (certo) |
| `fonte ativa: crowdsec` (suricata, falco) | detecção em tempo real ligada |
| `notificador ativo: telegram (a partir de Alto)` | alertas configurados |
| `telegram: conversa ativa para 1 chat(s)` | bot responde comandos |
| `IA ativa: …` | IA configurada |
| `Relatório: /var/lib/sentinels/reports/…` | uma varredura terminou |

Pelo Telegram: `/doctor` (o que está ativo e o que falta), `/status`, `/inventory`.

## 2. Versão e atualização

```bash
docker compose exec sentinels sentinels version                         # versão rodando
curl -s https://api.github.com/repos/SantanaCharles/sentinels/releases/latest | grep tag_name   # mais nova
```

| Instalação | Atualizar |
|------------|-----------|
| Docker Compose | `docker compose pull sentinels && docker compose up -d --force-recreate sentinels` |
| Portainer (stack) | Stacks → sentinels → **Pull and redeploy** (Repository) ou Update the stack com "Re-pull image" |
| Portainer (Swarm) | Services → sentinels_sentinels → **Update the service** com "Re-pull image" |
| systemd | `sudo sh install.sh` (baixa a release mais nova e confere o SHA-256) |
| Comando no host (`--cli-only`) | `sudo sh install.sh --cli-only` |

Configuração e memória ficam no volume/pasta e são preservadas.

## 3. Testar a detecção (ataques simulados)

Requisito: CrowdSec ativo (`sudo sentinels setup install`). Faça os testes **de outra rede** (ex.:
celular no 4G): o IP de onde você configurou o SSH fica liberado no CrowdSec e não gera alerta.
O IP de teste **será bloqueado** — desbloqueie com `cscli decisions delete --ip <IP>`.
Teste só o **seu** servidor.

| Teste | Como | Resultado esperado |
|-------|------|--------------------|
| Fim a fim, sem atacar | `cscli decisions add --ip 192.0.2.10 --duration 5m --reason teste` | alerta no Telegram em segundos; limpe com `cscli decisions delete --ip 192.0.2.10` |
| Força bruta SSH | do celular, 6 tentativas de SSH com usuário inventado e senha errada | `[ALTO] Brute Force — crowdsecurity/ssh-bf (T1110)`; IP bloqueado |
| Varredura web | de outra rede: `for i in $(seq 1 30); do curl -s -o /dev/null https://SEU-SITE/nao-existe-$i; done` | `Active Scanning (T1595)`, nível Médio — veja em `/events` |
| Suricata | na VPS: `curl http://testmynids.org/uid/index.html` | regra *GPL ATTACK_RESPONSE id check returned root* em `/events` |
| Falco | `docker run -it --rm falcosecurity/event-generator run syscall` | vários alertas de comportamento em `/events` |
| Configuração | `docker run -d --name teste-sentinels --privileged alpine:3.20 sleep 900` e `/scan` | `Novo achado: Container privilegiado`; depois `docker rm -f teste-sentinels` |

Alertas a partir de **Alto** vão para o Telegram; os de nível Médio ficam em `/events`. Depois,
marque o evento como **✅ Ataque real** no Telegram.

## 4. Problemas comuns

| Sintoma | Causa | Solução |
|---------|-------|---------|
| `no configuration file provided: not found` | `docker compose` fora da pasta do compose | `cd ~/sentinels/deploy` ou `docker exec sentinels-sentinels-1 sentinels …` |
| `lendo containers em /var/run/docker.sock` + "não foi possível ler os containers" | `sentinels.yaml` antigo fixando o socket (versões ≤ 0.2.0) | `sed -i 's#socket: /var/run/docker.sock#socket: tcp://127.0.0.1:2375#' sentinels.yaml` e recrie; a partir da v0.2.1 o `DOCKER_HOST` sempre prevalece |
| Mudei chave/token e nada mudou | `docker compose restart` **não relê** o `sentinels.env` | `docker compose up -d --force-recreate sentinels` |
| Container reiniciando, log com "variável … vazia" | segredo não chegou ao container | confira o `sentinels.env` e recrie o container |
| Bot não responde comandos | canal sem `interactive: true` (criado antes da v0.2.0) | `sentinels setup notifications` → 💬 ativar conversa, salvar, recriar |
| Log: "webhook ativo" ou "outro processo está lendo este bot" (409) | o mesmo bot é usado no n8n (Telegram Trigger) ou por outro agente | crie um bot só para o Sentinels no @BotFather |
| Log: "mensagem ignorada do chat …" | você escreveu de um chat diferente do configurado | use o chat configurado ou refaça o canal no setup |
| `/scan` ou `/doctor` não existem | versão antiga (v0.2.0) | atualize (seção 2) |
| Portainer: "unsupported options: mem_limit" | ambiente Docker Swarm | use `deploy/portainer-stack-swarm.yml` |
| Menu do `setup` demora ~5 s no console web | o console não responde a consultas do terminal | espere, ou use `sentinels setup --plain` |
| `sentinels setup install` diz "rode no servidor" | você está dentro de um container | instale o comando no host: `sudo sh install.sh --cli-only` |
| Primeira varredura demorada | o Trivy baixa a base de vulnerabilidades | normal; as próximas são rápidas |
| Muitas CVEs no relatório | imagens desatualizadas | atualize as imagens base; CVEs do kernel dentro das imagens já são ignoradas |
| CrowdSec não sobe após instalar | porta 8080 ocupada | o `setup install` move a API para outra porta; rode-o de novo |
