# Inside applications and databases

How Sentinels watches what happens **inside** an application and its database — including when the
attacker is a logged-in user.

The network alone is not enough: the app → database connection usually has TLS, and a logged-in
user sends queries that come from the same database user the application uses. With an ORM (Prisma,
Eloquent, TypeORM…), SQL injection is rare; the typical attack from someone logged in is **IDOR** —
changing the ID in the URL to see another customer's data. That is why there are four layers, each
seeing one part.

| Layer | Catches | Needs |
|-------|---------|-------|
| 1. Database and application logs | SQL injection (with the query in the alert), a burst of SQL errors, RLS violation, access denied, dangerous commands, password brute force on the database, ID enumeration (IDOR), login brute force | nothing (on by default) |
| 2. Who talks to the database | a new container or an internet IP connecting to the database | host `/proc` mounted (ships in the `deploy/` files) |
| 3. Inside the containers (Falco) | a database or PHP spawning a shell, a webshell written, a database connecting outbound, attack tools, a miner, package installation | Falco + the Sentinels rules |
| 4. At the port, before the application (WAF) | known CVE exploits blocked on the spot; generic SQLi/XSS → IP ban | CrowdSec + the Traefik plugin |

Layers 3 and 4 are installed by `sudo sentinels setup install`, with each command shown and
confirmed first.

## 1. Database and application logs

Through the Docker API (read-only, via the socket-proxy) the agent reads the logs of the
**PostgreSQL** and **application** containers. Reverse proxies are left to CrowdSec. Nothing is read
from the applications' disk or from the database tables.

**PostgreSQL** — with the official image's default configuration, every query that errors shows up
in the log with the query text. The agent alerts on:

| Rule | When | Level |
|------|------|-------|
| `postgres-sqli-attempt` | a failed query containing `UNION SELECT`, `information_schema`, `pg_shadow`, `' OR '1'='1`, a stacked command (`; DROP`), `pg_sleep`… | Critical |
| `postgres-dangerous-command` | `COPY … PROGRAM`, `pg_read_file`, `lo_import`, `dblink`, `ALTER SYSTEM`, a function in C/an untrusted language | Critical |
| `postgres-sql-error-burst` | 5 syntax errors in 5 min (the pattern of someone probing for injection) | High |
| `postgres-rls-violation` | `new row violates row-level security policy` (writing another tenant's data) | High |
| `postgres-permission-denied` | access denied to a table/function; 10 in 5 min raises it to High | Medium |
| `postgres-auth-bruteforce` | 5 wrong passwords in 5 min | High |
| `postgres-external-connection` | `no pg_hba.conf entry` coming from an internet IP | High |

A common application error (a column that does not exist, for example) does **not** become an alert:
only errors that look like an attack, or bursts.

To catch SQL injection **by timing** (`pg_sleep(5)`), enable the slow-query log in Postgres — in the
service's `command`:

```yaml
command: ["postgres", "-c", "log_min_duration_statement=3000"]
```

**MySQL/MariaDB** do not log queries with errors by default; for them the application logs (below),
layers 2 to 4 and Falco apply.

**Application** — the agent understands the Apache/Nginx access format (PHP images) and JSON logs
(pino, winston, Laravel with the `stderr` channel in JSON…):

| Rule | When | Level |
|------|------|-------|
| `app-sqli-attempt` | a SQL error in the log (`SQLSTATE[`, `You have an error in your SQL syntax`, `QueryFailedError`…) with an injection snippet | Critical |
| `app-sql-error-burst` | 5 SQL errors in 5 min | High |
| `app-enumeration` | the same user (or IP) gets 30 403/404 responses across 10+ different addresses in 5 min — walking through IDs | High with a logged-in user, Medium with only an IP |
| `app-login-bruteforce` | 20 401 responses in 5 min | High |

For IDOR detection to work, **the application log must say who made the request**. Example of a line
the agent understands (Node with pino):

```json
{"req":{"method":"GET","url":"/api/pedidos/1042"},"res":{"statusCode":403},"userId":"u-77"}
```

Recognized fields: status in `status`/`statusCode`/`status_code`; user in
`userId`/`user_id`/`uid`/`user`/`username`/`sub`/`email` (or `user.id`); IP in
`ip`/`client_ip`/`remoteAddr`/`remoteAddress`; path in `path`/`url`/`uri`. Behind Traefik, with no
real user or IP in the log, the application cannot tell who is who — those lines are ignored.

Applications that do not log the requests (many on Next.js) are still covered by the SQL errors, by
RLS and by the other layers.

## 2. Who talks to the database

Every minute the agent reads the connection table of each database container (Postgres, MySQL,
Mongo, Redis…) in `/proc/<pid>/net/tcp`, with no password and without touching the database:

- in the first 30 minutes (or until the first client appears) it **learns** who connects —
  normally only the application;
- after that, a new client becomes a Medium `db-new-client` alert: "Novo cliente conectando no banco
  erp-db: estranho. Até agora só conectavam: erp-app";
- a connection coming **from the internet** becomes `db-external-client` (High) always, even during
  learning.

Clients are identified by the Compose or Swarm service, which does not change when the container is
recreated. The baseline lives in `/var/lib/sentinels/db-clients.json`; delete the file to relearn
from scratch.

On Docker, the agent needs the host's `/proc`, already present in the `deploy/` files:

```yaml
    volumes:
      - /proc:/host/proc:ro
```

The container stays without root and without capabilities; it just gets to **see** the host's
processes. On a systemd install nothing changes.

## 3. Inside the containers (Falco)

`setup install` → Falco writes `/etc/falco/rules.d/sentinels.yaml` and turns on `rule_matching: all`
in `/etc/falco/config.d/sentinels.yaml`. Without that option, the first rule that matches the event
"wins" — and Falco's default rule for a shell spawned by a database has a low priority (Notice).

| Rule | Level |
|------|-------|
| A database spawned a shell (`COPY … TO PROGRAM`, a malicious function, an exploited Redis) | Critical |
| PHP spawned a shell (RCE, webshell, PHP2Shell) — `mail()` is ignored | Critical |
| The web server wrote a `.php`/`.phtml`/`.phar`/`.jsp` in the site (webshell) | Medium |
| A database connected to the internet (exfiltration, reverse shell) | Critical |
| An attack tool in the container (`nmap`, `sqlmap`, `hydra`, `chisel`…) | Critical |
| A cryptocurrency miner | Critical |
| Package installation with the container running | Medium |
| A Node/Python/Ruby/Java application spawned a shell | Medium |

Falco is what catches the attack that **worked** — a `COPY … TO PROGRAM` run by a privileged user
generates no error in the database log, but it opens a shell.

Local tweaks go in `/etc/falco/rules.d/sentinels-local.yaml` (reinstalling overwrites
`sentinels.yaml`). To silence a specific alert, use 🔕 Falso positivo on Telegram.

## 4. CrowdSec WAF on Traefik

`setup install` → CrowdSec, when it finds Traefik, offers to enable **AppSec**:

1. installs the `appsec-virtual-patching`, `appsec-generic-rules` and `appsec-crs` (OWASP CRS) rules;
2. brings the component up on `docker0-IP:7422` — reachable by the containers, not by the internet;
3. creates the `traefik-appsec` key and shows the arguments and labels to paste into the Traefik
   stack (plugin `crowdsec-bouncer-traefik-plugin` pinned at v1.7.1). Sentinels does not edit
   Traefik: a mistake there takes every site down.

How it works, tested with the real CrowdSec:

- known CVE exploits and access to `/.env` are **blocked on the spot** (403);
- generic SQL injection, XSS and path traversal (OWASP CRS) do **not** block the request, so a
  legitimate user is not barred by mistake. After a few attempts the IP is **banned**
  (`crowdsec-appsec-outofband`) and the alert arrives on Telegram;
- if CrowdSec goes down, the sites stay up (`crowdsecappsecunreachableblock=false`).

## Testing (on your own server)

| Layer | How | Expected |
|-------|-----|----------|
| 1 | `docker exec <postgres-container> psql -U <user> -c "SELECT 1 UNION SELECT usename, passwd FROM pg_shadow--"` | `[CRÍTICO] postgres-sqli-attempt` with the query |
| 1 | the same command 5 times with `"SELECT * FROM x WHERE a = 'o'brien'"` | `[ALTO] postgres-sql-error-burst` |
| 2 | `docker run --rm --network <database-network> postgres:17-alpine pg_isready -h <database-service>` after the agent has run for 30 min | `[MÉDIO] db-new-client` in `/events` |
| 3 | `docker run --rm php:8.3-cli-alpine php -r 'echo shell_exec("id");'` | `[CRÍTICO] Sentinels PHP spawned shell` |
| 4 | from another network: `curl -s -o /dev/null -w '%{http_code}' https://YOUR-SITE/.env` | `403` |

## Privacy

- Only the lines that become an alert are kept, cut at ~240 characters. The rest of the log is read
  and discarded.
- Before anything is sent to the AI, secrets are masked and IPs/emails pseudonymized.
- To take a container out of log reading: `integrations.containers.exclude: [name]`. To turn off a
  part: `logs: false` or `db_clients: false`.
