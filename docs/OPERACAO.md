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

Pelo Telegram: `/doctor` (o que está ativo e o que falta), `/status`, `/inventory`, `/metrics`.

### Sinal de vida e monitor externo

Um agente parado não alerta nada, então ele avisa que está vivo:

- `alerts.heartbeat: 24h` manda "🟢 Sentinels ativo" em todos os canais (com tempo no ar, eventos
  desde o último aviso e críticos abertos). **Se a mensagem não chegar no horário, o agente ou o servidor caiu.**
- Para ser avisado sem depender de notar a ausência, crie um check no [healthchecks.io](https://healthchecks.io)
  ou um monitor "push" no Uptime Kuma, coloque a URL em `SENTINELS_HEARTBEAT_URL` no `sentinels.env` e
  `alerts.heartbeat_url_env: SENTINELS_HEARTBEAT_URL` no YAML. O agente acessa a URL a cada 5 minutos;
  se parar, o monitor avisa você.

Os dois ficam em `sentinels setup scan`.

### Relatório diário por país

`alerts.daily_report: "08:00"` (hora local) manda, uma vez por dia, um resumo do **dia anterior** em
todos os canais: total de eventos e a quebra por severidade, **origem dos ataques por país**, os IPs e
as técnicas (ATT&CK) mais ativos, e o que segue em aberto. Vazio desliga.

A origem por país vem de uma base GeoIP lida **offline** (nenhum IP sai da máquina):

- o `GeoLite2` que o CrowdSec já instala em `/var/lib/crowdsec/data/`, quando presente (instalação via
  systemd); ou
- a base **DB-IP Lite Country** (CC-BY — [db-ip.com](https://db-ip.com)) que o `sentinels setup install`
  baixa para `/var/lib/sentinels/dbip-country.mmdb` — é o caminho usado no Docker e em servidores sem
  CrowdSec. Ela é mensal; rode o passo de novo para atualizá-la.

Para apontar uma base `.mmdb` específica, use `alerts.geoip_db`. Sem nenhuma base, o relatório ainda sai,
agrupando apenas por IP.

### O que a varredura também verifica sobre o próprio agente

| Achado | Quando |
|--------|--------|
| `tls.expired` / `tls.expiring` | certificado vencido ou vencendo em menos de 14 dias (alto em menos de 7) |
| `tls.invalid` / `tls.old_protocol` | certificado que não bate com o domínio, autoassinado, ou servidor aceitando TLS < 1.2 |
| `agent.stale_trivy_db` | base de CVEs do Trivy com mais de 3 dias |
| `agent.stale_advisories` / `agent.stale_kev` | feed de alertas emergenciais / catálogo CISA KEV sem atualizar |
| `agent.stale_suricata_rules` / `agent.stale_crowdsec_hub` | regras do Suricata com mais de 7 dias / hub do CrowdSec com mais de 14 |

Os domínios verificados são os de `scan.urls` **mais** os descobertos sozinhos nos labels do Traefik
(`Host(...)`) e do Caddy, dos containers e dos serviços do Swarm (até 30). Para ler os serviços do Swarm,
o socket-proxy precisa de `SERVICES: 1` — já vem nos arquivos de `deploy/`.

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

> **Vindo da v0.2.2 ou anterior:** copie o `deploy/` novo, ou faça à mão no `docker-compose.yml`:
> `SERVICES: 1` no `environment` do `socket-proxy` (domínios dos serviços do Swarm) e
> `- /proc:/host/proc:ro` nos `volumes` do `sentinels` (quem conecta em cada banco). Depois
> `docker compose up -d --force-recreate`. Sem isso o resto funciona normalmente.

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
| SQL injection no banco | `docker exec <container-do-postgres> psql -U <usuario> -c "SELECT 1 UNION SELECT usename, passwd FROM pg_shadow--"` | `[CRÍTICO] postgres-sqli-attempt` com a consulta |
| PHP abrindo shell (Falco) | `docker run --rm php:8.3-cli-alpine php -r 'echo shell_exec("id");'` | `[CRÍTICO] Sentinels PHP spawned shell` |
| WAF (CrowdSec + Traefik) | de outra rede: `curl -s -o /dev/null -w '%{http_code}' https://SEU-SITE/.env` | `403` |
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
| Log: "conexões dos bancos indisponíveis" | o container do agente não vê o `/proc` do host | acrescente `- /proc:/host/proc:ro` aos volumes do serviço `sentinels` (já vem no `deploy/` novo) e recrie |
| Alerta `db-new-client` de um serviço que você mesmo subiu | a linha de base aprendeu antes dele existir | marque 🔕 Falso positivo; para reaprender tudo, apague `/var/lib/sentinels/db-clients.json` |
| Nenhum alerta de banco com SQL injection testado | o container não é Postgres, ou a consulta não deu erro | só consultas com erro aparecem no log; veja docs/APLICACOES.md |
