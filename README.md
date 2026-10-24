# Sentinels

**Free and open-source** security agent for servers and VPSs. Install it on your server and it:

1. **Discovers** your containers and published apps and identifies each one's stack.
2. **Audits** their configuration and produces a report of critical vulnerabilities.
3. **Monitors** attack signals in real time, collected by proven open-source engines.
4. **Alerts** administrators (Telegram, Slack, Discord, e-mail or webhook) — and lets them reply from Telegram.
5. **Explains** findings with the AI of your choice — Claude, GPT, Gemini, OpenRouter, Ollama, LM Studio.

> Status: **v0.2 — ready for testing on real servers.** See the [roadmap](#roadmap).
> The user interface (setup menus, alerts, bot replies) and the detailed docs in `docs/` are
> currently in Brazilian Portuguese; commands and configuration keys are in English.

---

## Why Sentinels

Small teams ship apps to a Docker VPS and rarely have time to audit configuration, track CVEs
and read logs. Sentinels bundles those jobs into one lightweight agent — free, and sending data
nowhere except where you configure it to.

## Principles

- **Don't reinvent detection.** Known attack signatures are maintained by mature projects
  (Trivy, CrowdSec, Suricata, Falco). Sentinels integrates, correlates and alerts.
- **AI off the critical path.** Detection works without AI. The AI only summarizes reports and
  explains alerts; it never takes actions on the server.
- **Private by default.** Secret values are never read or sent — only their names. Anything sent
  to an AI is redacted first.
- **Read-only.** The agent observes and alerts. It does not block traffic or modify containers.
- **One binary, no dependencies.** Written in Go.

## What it checks

| Area | Examples |
|------|----------|
| Containers | privileged containers, mounted `docker.sock`, running as root, host network |
| Exposure | databases or admin panels reachable from the internet |
| Images | known CVEs via Trivy |
| Leaked keys | API keys, tokens and private keys baked into images (files and build history), `.env`/`.git` served by the website, secrets in environment variables — values are never read or stored |
| Web | missing security headers, exposed server version, permissive CORS |
| Database (PostgreSQL) | multi-tenant tables without Row-Level Security, RLS without `FORCE`, app connecting as owner/superuser |
| Real time | CrowdSec, Suricata and Falco alerts correlated per container/app |

## Knowledge bases

| Source | Used for |
|--------|----------|
| CIS Docker Benchmark | reference for the container checks |
| OWASP Top 10 / ASVS | web checks |
| Emergency advisories | critical flaws exploited **before** they reach KEV (e.g. PHP2Shell, Oct 2026) — signed feed |
| CISA KEV | actively exploited CVEs are raised to **Critical** |
| EPSS | exploitation probability, to order what to fix first |
| MITRE ATT&CK | standard technique name on every alert |
| CWE | weakness type and remediation reference |

## Security skills for the AI

`SKILL.md` files (the open Agent Skills format) with focused knowledge — alert triage,
Docker/VPS hardening, PostgreSQL RLS, incident response, LGPD (Brazilian data-protection law).
Sentinels sends the relevant skills along with the context, so it works with any provider. Add
your own in `/etc/sentinels/skills/` — see [docs/SKILLS.md](docs/SKILLS.md).

Built in: `triagem-alertas`, `resposta-incidentes`, `lgpd-incidentes`, `postgres-rls`,
`hardening-docker`, `hardening-vps`, `php-seguranca`, `seguranca-web`.

## Installation

**Docker Compose** (recommended — ships with Trivy and talks to Docker through a read-only
proxy instead of the Docker socket):

```bash
git clone https://github.com/SantanaCharles/sentinels && cd sentinels/deploy
cp sentinels.docker.yaml sentinels.yaml
cp sentinels.env.example sentinels.env && chmod 600 sentinels.env
docker compose up -d
```

**Portainer**: Stacks → Add stack → paste [`deploy/portainer-stack.yml`](deploy/portainer-stack.yml)
(or [`deploy/portainer-stack-swarm.yml`](deploy/portainer-stack-swarm.yml) on **Docker Swarm**)
and configure it from the container console (`sentinels setup`). Step by step in
[docs/INSTALACAO.md](docs/INSTALACAO.md#opção-a2--portainer-stack).

**Binary + systemd** (verifies the SHA-256 of every file before installing):

```bash
curl -fsSL https://github.com/SantanaCharles/sentinels/releases/latest/download/install.sh -o install.sh
sudo sh install.sh
sudo systemctl enable --now sentinels
```

Details, hardening and upgrades: [docs/INSTALACAO.md](docs/INSTALACAO.md).

## Getting started: `sentinels setup`

```bash
sudo sentinels setup              # arrow-key menu: ↑ ↓ to move, Enter to select
sudo sentinels setup ai           # jump to a section: quick, ai, notifications, integrations, databases, scan, vault, mcp
```

| Section | What you configure |
|---------|--------------------|
| `quick` | AI + one alert channel + a test, in two minutes |
| `ai` | provider, model, API key and usage limits |
| `notifications` | Telegram, Slack, Discord, e-mail, webhook — and Telegram chat |
| `integrations` | Trivy, CrowdSec, Suricata, Falco |
| `databases` | PostgreSQL Row-Level Security audit |
| `scan` | interval, alert severity, public URLs |
| `vault` | Obsidian-compatible notes |
| `mcp` | query the agent from Claude/ChatGPT |

- **Real model list**: fetched from the provider's API — type `/` to filter.
- **No hunting for the Telegram chat_id**: create the bot with @BotFather, send it a message, and
  setup finds the conversation.
- **Tests on the spot**: AI, every alert channel, and the database connection.
- **Secrets kept apart**: keys and tokens go to `sentinels.env` (0600), never to the YAML;
  password fields are not echoed. The previous configuration is kept as `.bak`.
- Without an interactive terminal (or with `--plain`) it falls back to simple line-by-line prompts.

For scripts: `sentinels config show`, `config get ai.model`, `config set alerts.min_severity critical`,
`config set-secret SENTINELS_AI_KEY` (reads without echo).

## Chat with the agent on Telegram

With chat enabled (`sentinels setup notifications` → 💬), the bot answers:

| Command | Reply |
|---------|-------|
| `/status` | server summary: last scan, open critical findings, events in the last 24 h |
| `/scan` | acknowledges right away, runs a full scan and sends the status when it finishes |
| `/inventory` · `/inventory php` | what is running: containers, image, stack, public ports and open problems |
| `/findings` · `/findings critical` · `/findings all` | open findings |
| `/events` · `/events 72` | recent attacks and events, numbered |
| `/event 12` | event details, AI analysis and buttons |
| `/muted` | active false-positive rules |
| `/help` | help |
| any question | answered by your AI, e.g. *"what happened today?"* |

Alerts carry **✅ Real attack · 🔕 False positive · 🤖 Explain** buttons. The bot only answers the
configured chat, opens no port on the server (long polling), and never changes anything on the
server. Details in [docs/TELEGRAM.md](docs/TELEGRAM.md).

## Usage

```bash
sentinels scan                  # full scan + report (Markdown and JSON)
sentinels scan --offline        # without downloading KEV/EPSS/advisory feed
sentinels scan --fail-on high   # exit code 3 if there is a High or Critical finding (CI)
sentinels watch                 # real time + periodic scans, correlation and alerts
sentinels watch --json          # alerts as JSON lines
sentinels events --since 24h --min low   # history kept in the local store
sentinels notify-test           # send a test alert to every channel
sentinels ai-test               # test the configured AI and list loaded skills
sentinels explain 42            # AI analysis of an event
sentinels mcp                   # MCP server: ask Claude/ChatGPT about the server (docs/MCP.md)
sentinels doctor                # check installed integrations
sentinels version
```

### Teaching the agent

```bash
sentinels feedback 42 fp --note "internal monitoring"   # false positive: mutes identical events for 30 days
sentinels feedback 42 fp --scope rule                    # mute the rule on any target/IP
sentinels feedback 57 confirmed                          # real attack: the source IP weighs more for 90 days
sentinels suppressions                                   # list mutes (remove: suppressions remove <id>)
sentinels findings                                       # open findings, with each one's key
sentinels accept "container.root_user|db" --reason "official image drops privileges in its entrypoint"
```

A mute **never** silences an exploitation attempt against a target with a known vulnerability —
that safety net cannot be switched off by feedback.

## Connecting an AI

```yaml
ai:
  enabled: true
  provider: anthropic        # anthropic | openai | gemini | openrouter | ollama | lmstudio | openai-compatible
  model: claude-sonnet-5-5
  api_key_env: SENTINELS_AI_KEY
```

| Provider | `provider` | API key |
|----------|-----------|---------|
| Claude | `anthropic` | yes |
| GPT | `openai` | yes |
| Gemini | `gemini` | yes |
| OpenRouter (any model) | `openrouter` | yes |
| Ollama / LM Studio (local — nothing leaves the server) | `ollama` / `lmstudio` | no |
| Groq, Together, vLLM… | `openai-compatible` + `base_url` | depends on the service |

What the AI does:
- **Executive summary** at the top of each report, with the top 5 priorities.
- **Analysis of severe alerts** (default: Critical), sent as a second message — the original
  alert never waits for the AI. Hourly call cap to control cost.
- `sentinels explain <event>` and the Telegram 🤖 button — on-demand analysis of any stored event.

Before anything leaves the server it is redacted: passwords, tokens, keys (AWS, Stripe, GitHub,
Google, Telegram), JWTs and CPFs are removed; IPs and e-mails become pseudonyms (`[IP-1]`).
The API key is read from an environment variable, never from the configuration file.

## Obsidian vault

With `vault.enabled: true` the agent keeps a folder of Markdown notes: reports, one incident per
alert (with the AI analysis), one note per asset and per ATT&CK technique, all linked with
`[[links]]` — Obsidian's graph shows which attack hit which app. Whatever you write below the
administrator-notes marker is preserved. Text coming from logs always sits in code blocks, so
nothing injected by an attacker is rendered.

## Documentation (Portuguese)

- [Installation](docs/INSTALACAO.md)
- [Architecture](docs/ARQUITETURA.md)
- [Security policy](SECURITY.md)
- [Real-time integrations (CrowdSec, Suricata, Falco)](docs/INTEGRACOES.md)
- [Writing skills](docs/SKILLS.md)
- [MCP server (Claude Code, Claude Desktop, ChatGPT…)](docs/MCP.md)
- [Telegram chat](docs/TELEGRAM.md)

## Roadmap

- [x] 1 — Project foundation and docs
- [x] 2 — Scanning (containers, stack, exposure, RLS, CVEs via Trivy) with CIS, CWE, CISA KEV, EPSS and emergency advisories
- [x] 3 — Real time: CrowdSec, Suricata and Falco, alerts classified with MITRE ATT&CK, local SQLite store
- [x] 4 — Alerts (Telegram, Slack, Discord, e-mail, webhook) + admin feedback (false positive / confirmed)
- [x] 5 — AI providers + security skills (`SKILL.md`) + Obsidian-compatible vault
- [x] 6 — Installer, systemd service, Docker image and signed advisory feed
- [x] 7 — Read-only MCP server + AI-drafted emergency advisories
- [x] Setup wizard, leaked-key detection, Portainer/Swarm stacks, Telegram chat

Next: English interface, baseline of normal traffic, version detection for more runtimes
(Node.js, Java, Python) in emergency advisories.

## License

[Apache-2.0](LICENSE) — free to use, including commercially.

Made by [Smart Code Tecnologia](https://smartcodetecnologia.com.br).
