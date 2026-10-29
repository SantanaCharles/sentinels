# Operations: check, upgrade, test and troubleshoot

Commands for the **Docker Compose** install (run them inside the `~/sentinels/deploy` folder).
On **systemd**, replace `docker compose exec sentinels sentinels …` with `sudo -u sentinels sentinels … -config /etc/sentinels/sentinels.yaml`
and `docker compose up -d --force-recreate sentinels` with `sudo systemctl restart sentinels`.

## 1. Is it working?

```bash
cd ~/sentinels/deploy
docker compose ps                                   # sentinels and socket-proxy "Up" (not "Restarting")
docker compose exec sentinels sentinels version
docker compose exec sentinels sentinels doctor -config /etc/sentinels/sentinels.yaml
docker compose exec sentinels sentinels notify-test -config /etc/sentinels/sentinels.yaml
docker compose logs --tail 40 sentinels
```

In the log, look for:

| Line | Means |
|------|-------|
| `lendo containers em tcp://127.0.0.1:2375` | using the read-only proxy (correct) |
| `fonte ativa: crowdsec` (suricata, falco) | real-time detection on |
| `notificador ativo: telegram (a partir de Alto)` | alerts configured |
| `telegram: conversa ativa para 1 chat(s)` | bot answers commands |
| `IA ativa: …` | AI configured |
| `Relatório: /var/lib/sentinels/reports/…` | a scan finished |

From Telegram: `/doctor` (what is active and what is missing), `/status`, `/inventory`, `/metrics`.

### Heartbeat and external monitor

A stopped agent alerts nothing, so it announces that it is alive:

- `alerts.heartbeat: 24h` sends "🟢 Sentinels ativo" on every channel (with uptime, events since the
  last notice and open criticals). **If the message does not arrive on time, the agent or the server
  is down.**
- To be warned without having to notice the absence yourself, create a check on
  [healthchecks.io](https://healthchecks.io) or a "push" monitor on Uptime Kuma, put the URL in
  `SENTINELS_HEARTBEAT_URL` in `sentinels.env` and `alerts.heartbeat_url_env: SENTINELS_HEARTBEAT_URL`
  in the YAML. The agent hits the URL every 5 minutes; if it stops, the monitor warns you.

Both live in `sentinels setup scan`.

### Daily report by country

`alerts.daily_report: "08:00"` (local time) sends, once a day, a summary of the **previous day** on
every channel: total events and the breakdown by severity, **attack origin by country**, the most
active IPs and techniques (ATT&CK), and what is still open. Empty turns it off.

The origin by country comes from a GeoIP database read **offline** (no IP leaves the machine):

- the `GeoLite2` that CrowdSec already installs in `/var/lib/crowdsec/data/`, when present (systemd
  install); or
- the **DB-IP Lite Country** database (CC-BY — [db-ip.com](https://db-ip.com)) that
  `sentinels setup install` downloads to `/var/lib/sentinels/dbip-country.mmdb` — this is the path
  used on Docker and on servers without CrowdSec. It is monthly; run the step again to update it.

To point at a specific `.mmdb` database, use `alerts.geoip_db`. With no database, the report still
goes out, grouping only by IP.

### What the scan also checks about the agent itself

| Finding | When |
|---------|------|
| `tls.expired` / `tls.expiring` | certificate expired or expiring in less than 14 days (high under 7) |
| `tls.invalid` / `tls.old_protocol` | certificate that does not match the domain, self-signed, or a server accepting TLS < 1.2 |
| `agent.stale_trivy_db` | Trivy CVE database older than 3 days |
| `agent.stale_advisories` / `agent.stale_kev` | emergency alert feed / CISA KEV catalog not updated |
| `agent.stale_suricata_rules` / `agent.stale_crowdsec_hub` | Suricata rules older than 7 days / CrowdSec hub older than 14 |

The checked domains are those in `scan.urls` **plus** the ones discovered on their own in the Traefik
(`Host(...)`) and Caddy labels, from containers and Swarm services (up to 30). To read the Swarm
services, the socket-proxy needs `SERVICES: 1` — it already ships in the `deploy/` files.

### Host OS vulnerabilities

The scan also checks the **server's own OS packages** for known CVEs (Trivy `rootfs`), kernel
included — complementing the image CVEs. It is controlled by `scan.host_os` (`auto` by default,
`true` or `false`):

- **systemd install**: the agent runs on the host, so it scans `/` with no extra step.
- **Docker install**: the distroless container does not see the host filesystem. To enable it, mount
  the host root read-only and point the agent at it — add to the `sentinels` service in
  `docker-compose.yml`:

  ```yaml
      volumes:
        - /:/host/root:ro
  ```

  and set `scan.host_root: /host/root` in `sentinels.yaml`, then
  `docker compose up -d --force-recreate sentinels`. With `host_os: auto` and no mount, the host OS
  scan is simply skipped (the report says `CVEs do SO do host não`).

Host CVEs appear under the target `host`; the remediation is a system package upgrade
(`apt upgrade` / `dnf upgrade`), and kernel CVEs note that a reboot is required.

## 2. Version and upgrade

```bash
docker compose exec sentinels sentinels version                         # running version
curl -s https://api.github.com/repos/SantanaCharles/sentinels/releases/latest | grep tag_name   # newest
```

| Install | Upgrade |
|---------|---------|
| Docker Compose | `docker compose pull sentinels && docker compose up -d --force-recreate sentinels` |
| Portainer (stack) | Stacks → sentinels → **Pull and redeploy** (Repository) or Update the stack with "Re-pull image" |
| Portainer (Swarm) | Services → sentinels_sentinels → **Update the service** with "Re-pull image" |
| systemd | `sudo sh install.sh` (downloads the newest release and checks the SHA-256) |
| Command on the host (`--cli-only`) | `sudo sh install.sh --cli-only` |

Configuration and memory live in the volume/folder and are preserved.

> **Coming from v0.2.2 or earlier:** copy the new `deploy/`, or do it by hand in `docker-compose.yml`:
> `SERVICES: 1` in the `socket-proxy` `environment` (Swarm service domains) and
> `- /proc:/host/proc:ro` in the `sentinels` `volumes` (who connects to each database). Then
> `docker compose up -d --force-recreate`. Without this, the rest works normally.

## 3. Test detection (simulated attacks)

Requirement: CrowdSec active (`sudo sentinels setup install`). Run the tests **from another network**
(e.g. a phone on 4G): the IP you configured SSH from is whitelisted in CrowdSec and generates no
alert. The test IP **will be blocked** — unblock it with `cscli decisions delete --ip <IP>`.
Only test **your own** server.

| Test | How | Expected result |
|------|-----|-----------------|
| End to end, no attack | `cscli decisions add --ip 192.0.2.10 --duration 5m --reason teste` | alert on Telegram in seconds; clear it with `cscli decisions delete --ip 192.0.2.10` |
| SSH brute force | from the phone, 6 SSH attempts with a made-up user and a wrong password | `[ALTO] Brute Force — crowdsecurity/ssh-bf (T1110)`; IP blocked |
| Web scan | from another network: `for i in $(seq 1 30); do curl -s -o /dev/null https://YOUR-SITE/does-not-exist-$i; done` | `Active Scanning (T1595)`, Medium level — see it in `/events` |
| Suricata | on the VPS: `curl http://testmynids.org/uid/index.html` | rule *GPL ATTACK_RESPONSE id check returned root* in `/events` |
| Falco | `docker run -it --rm falcosecurity/event-generator run syscall` | several behavior alerts in `/events` |
| SQL injection on the database | `docker exec <postgres-container> psql -U <user> -c "SELECT 1 UNION SELECT usename, passwd FROM pg_shadow--"` | `[CRÍTICO] postgres-sqli-attempt` with the query |
| PHP spawning a shell (Falco) | `docker run --rm php:8.3-cli-alpine php -r 'echo shell_exec("id");'` | `[CRÍTICO] Sentinels PHP spawned shell` |
| WAF (CrowdSec + Traefik) | from another network: `curl -s -o /dev/null -w '%{http_code}' https://YOUR-SITE/.env` | `403` |
| Configuration | `docker run -d --name teste-sentinels --privileged alpine:3.20 sleep 900` and `/scan` | `Novo achado: Container privilegiado`; then `docker rm -f teste-sentinels` |

Alerts of **High** and above go to Telegram; Medium ones stay in `/events`. Afterwards, mark the
event as **✅ Ataque real** on Telegram.

## 4. Common problems

| Symptom | Cause | Fix |
|---------|-------|-----|
| `no configuration file provided: not found` | `docker compose` outside the compose folder | `cd ~/sentinels/deploy` or `docker exec sentinels-sentinels-1 sentinels …` |
| `lendo containers em /var/run/docker.sock` + "não foi possível ler os containers" | old `sentinels.yaml` pinning the socket (versions ≤ 0.2.0) | `sed -i 's#socket: /var/run/docker.sock#socket: tcp://127.0.0.1:2375#' sentinels.yaml` and recreate; from v0.2.1 on, `DOCKER_HOST` always wins |
| Changed a key/token and nothing changed | `docker compose restart` **does not re-read** `sentinels.env` | `docker compose up -d --force-recreate sentinels` |
| Container restarting, log with "variável … vazia" | the secret did not reach the container | check `sentinels.env` and recreate the container |
| Bot does not answer commands | channel without `interactive: true` (created before v0.2.0) | `sentinels setup notifications` → 💬 enable chat, save, recreate |
| Log: "webhook ativo" or "outro processo está lendo este bot" (409) | the same bot is used in n8n (Telegram Trigger) or by another agent | create a bot just for Sentinels in @BotFather |
| Log: "mensagem ignorada do chat …" | you wrote from a chat other than the configured one | use the configured chat or redo the channel in setup |
| `/scan` or `/doctor` do not exist | old version (v0.2.0) | upgrade (section 2) |
| Portainer: "unsupported options: mem_limit" | Docker Swarm environment | use `deploy/portainer-stack-swarm.yml` |
| The `setup` menu takes ~5 s on the web console | the console does not answer terminal queries | wait, or use `sentinels setup --plain` |
| `sentinels setup install` says "rode no servidor" | you are inside a container | install the command on the host: `sudo sh install.sh --cli-only` |
| Slow first scan | Trivy is downloading the vulnerability database | normal; the next ones are fast |
| Many CVEs in the report | outdated images | update the base images; kernel CVEs inside the images are already ignored |
| CrowdSec does not come up after installing | port 8080 in use | `setup install` moves the API to another port; run it again |
| Log: "conexões dos bancos indisponíveis" | the agent container does not see the host's `/proc` | add `- /proc:/host/proc:ro` to the `sentinels` service volumes (ships in the new `deploy/`) and recreate |
| `db-new-client` alert for a service you brought up yourself | the baseline was learned before it existed | mark 🔕 Falso positivo; to relearn everything, delete `/var/lib/sentinels/db-clients.json` |
| No database alert with the SQL injection test | the container is not Postgres, or the query did not error | only queries that error show up in the log; see docs/APPLICATIONS.md |
