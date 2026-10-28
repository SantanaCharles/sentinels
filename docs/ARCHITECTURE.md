# Sentinels architecture

## Overview

```
                    ┌──────────────────────── Server / VPS ──────────────────────────┐
                    │                                                                │
  Docker Engine ───►│  Discovery ──► Fingerprint ──► Checks ──┐                      │
  (read-only)       │                                         ▼                      │
                    │                                    Findings ──► Report (MD/JSON)│
  Trivy ───────────►│  Integrations ─────────────────────────▲                      │
                    │                                         │                      │
  CrowdSec ────────►│                                         │                      │
  Suricata (eve) ──►│  Watch (events) ──► Correlation ──► Alert ──► Notifiers ──────┼──► Telegram/Slack/
  Falco ───────────►│                                         │                      │    Discord/Email/Webhook
                    │                                         ▼                      │
                    │                                  AI (optional, async) ────────┼──► Claude/GPT/Gemini/
                    │                                                                │    OpenRouter/Ollama
                    └────────────────────────────────────────────────────────────────┘
```

## Modules

| Package | Responsibility |
|---------|----------------|
| `cmd/sentinels` | CLI: `scan`, `watch`, `doctor`, `version` |
| `internal/config` | Loads `sentinels.yaml` and environment variables |
| `internal/discovery` | Lists containers via the Docker API (Unix socket, read-only) and listening ports |
| `internal/fingerprint` | Identifies the stack: image, ports, HTTP headers, labels |
| `internal/checks` | Configuration checks; each one returns `Finding`s |
| `internal/integrations` | Adapters for Trivy, CrowdSec, Suricata, Falco |
| `internal/watch` | Continuous monitoring loop and event correlation |
| `internal/alert` | Deduplication, rate limiting and delivery to the notifiers |
| `internal/intel` | Public databases: CISA KEV, EPSS (with a 24h local cache) |
| `internal/event` | The `Event` type and MITRE ATT&CK mapping |
| `internal/store` | Local SQLite memory: events, finding state |
| `internal/ai` | Single AI provider layer |
| `internal/skills` | Loads and selects `SKILL.md` skills |
| `internal/mcp` | Read-only MCP server |
| `internal/report` | Markdown and JSON report |

## Data model

```go
type Severity int // Info, Low, Medium, High, Critical

type Finding struct {
    ID          string   // e.g. "container.privileged"
    Severity    Severity
    Target      string   // container, URL or table
    Title       string
    Detail      string
    Remediation string
    References  []string
    CIS         string   // e.g. "5.4" (CIS Docker Benchmark v1.6)
    CWE         []string // e.g. ["CWE-250"]
    CVE         string   // for Trivy findings
    KEV         bool     // present in the CISA KEV catalog
    EPSS        float64  // 0..1
}

type Event struct {          // real-time signal from an integration
    Source    string         // crowdsec | suricata | falco
    Severity  Severity
    Time      time.Time
    SourceIP  string
    Target    string         // correlated container/application
    Summary   string
    Technique string         // MITRE ATT&CK, e.g. "T1110"
    Raw       json.RawMessage // kept locally, never sent without redaction
}
```

## Decisions

### Detection delegated to mature projects
Writing and maintaining signatures for "every known attack" is the work of entire communities.
Sentinels consumes the output of those tools (all free) and adds value in three places:
**correlation** (which container/application was the target), **context** (the stack and the
vulnerabilities already known for that target) and a **unified alert**.

| Tool | Covers |
|------|--------|
| Trivy | CVEs in images and dependencies |
| CrowdSec | malicious patterns in web and SSH logs, IP reputation |
| Suricata | network traffic (open rules) |
| Falco | suspicious behavior inside containers |

Each integration is optional; `sentinels doctor` shows which ones are available.

### AI optional and with no power to act
- Detection and alerts work without AI.
- The AI receives only already-redacted text (internal IPs, tokens, emails and secrets masked) and
  returns only text. It does not call tools or run commands.
- Event content can be controlled by an attacker; it is sent as delimited, truncated data, and the
  AI's response is never interpreted as an instruction.
- Providers: Anthropic, OpenAI, Gemini and any OpenAI-compatible API (OpenRouter, Ollama,
  LM Studio, Groq) via `base_url`.

### Knowledge bases
Each `Finding` carries standardized references so the administrator knows where the rule comes from:

| Base | Where it appears |
|------|------------------|
| CIS Docker Benchmark v1.6 | `CIS` field in container checks |
| OWASP Top 10 / ASVS | `References` field in web checks |
| CWE | `CWE` field (from Trivy for CVEs; fixed in the built-in checks) |
| CISA KEV | CVE present in the catalog → **Critical** severity and a `KEV` mark |
| EPSS | score from 0 to 1; ≥ 0.5 raises it to at least **High**; orders the report |
| MITRE ATT&CK | `Technique` field in real-time `Event`s (stage 3) |

KEV and EPSS are downloaded from official sources (CISA and FIRST) and cached locally for 24h.
Without internet, the report is generated without that enrichment and says so at the top.

### Emergency alerts
KEV takes days to include a new flaw. Real case: PHP2Shell (CVE-2026-109618 and CVE-2026-109619,
PHP, 2026-10-21) had exploitation attempts reported and was still outside KEV on 10-22. To cover
that window Sentinels keeps `internal/intel/advisories.json`:

- a list **embedded in the binary** (works offline);
- a **feed** in the repository, downloaded every 6h, so installed agents get new alerts without a
  new version;
- the feed only **adds** alerts: it does not replace the embedded ones, so a tampered feed cannot
  silence an alert;
- the feed is **signed with Ed25519** (`advisories.json.sig`); the public key is in the binary and
  content without a valid signature is never used nor cached (`cmd/feedsign` signs it);
- matching by product and version, with the version coming from the `PHP_VERSION` variable of the
  official images or from the `X-Powered-By` header. Distribution versions (`8.3.6-1ubuntu…`) get
  "confirm the vendor patch", because Debian/Ubuntu fix without changing the number.

PHP applications (WordPress, Moodle, Nextcloud, GLPI, Laravel…) are identified by the image and
always go through this check; with no visible version, the report asks for a manual check.

### Security skills
Directories with a `SKILL.md` (frontmatter `name` + `description`, Markdown body), embedded in the
binary and complemented by `/etc/sentinels/skills/`. For each AI task (summarize report, triage
alert, suggest a fix) Sentinels picks the skills by their `description` and includes them in the
system prompt. That way the same knowledge works for any provider.

Initial skills: `triagem-alertas`, `hardening-docker`, `hardening-vps`, `postgres-rls`,
`resposta-incidentes`, `lgpd-incidentes`.

### MCP server (stage 7)
`sentinels mcp` implements the Model Context Protocol (JSON-RPC 2.0; versions 2024-11-05 to
2025-11-25) with 7 query tools — details in [MCP.md](MCP.md).
- **Truly read-only**: SQLite is opened with `mode=ro`; no tool writes.
- **stdio** (default, usually over `ssh`) or **Streamable HTTP** with a mandatory token, localhost
  by default, `Origin` verification.
- Responses redacted as with the AI (secrets, `[IP-n]`), log fields marked as untrusted, output
  capped at 60 KB.
- Validated with the official MCP Inspector (`--cli`: initialize, tools/list, tools/call).

### Emergency alert draft (stage 7)
`feedsign draft -in <advisory>` asks the AI for the feed entry and validates it: the format of each
field, and every CVE, fixed version and URL **must appear in the source text**. A product with no
version detection in the agent is flagged (`intel.SupportedProducts`). Adding to the feed and
signing are manual.

### How the agent learns
"Learning" is not training a model. There are three sources, each with its place:

| What | Where | How |
|------|-------|-----|
| New threats in the world | public feeds | emergency alerts, KEV, EPSS and updated rules from CrowdSec, Suricata (`suricata-update`) and Falco |
| What is normal for this server | local SQLite | history of events and findings (new × recurring × resolved); baseline of IPs/ports/volume (stage 4+) |
| What the admin teaches | local SQLite | false positive / confirmed on each alert (stage 4) |

**Memory: embedded SQLite** (`/var/lib/sentinels/sentinels.db`, pure-Go driver, no server). Stores
events with deduplication, the state of each finding across scans and, later, feedback and the
baseline. Default retention of 90 days.

**Window: Obsidian-compatible vault** (optional, stage 5). The agent writes reports, incidents and
one note per application in Markdown with `[[...]]` links; the admin opens the folder in Obsidian.
Obsidian is not the brain: it does not run on a headless server and does not answer the queries the
agent makes continuously.

**Safeguards**
- *Baseline poisoning*: learning only within a defined initial window, and nothing that matched an
  attack signature enters as "normal".
- The AI **suggests**, the human **approves**. No AI-created rule goes to production on its own.
- Stored events contain attacker-controlled text; they go back to the AI only as data.

### Real time (stage 3)

```
CrowdSec LAPI ──(poll /v1/decisions/stream)──┐
Suricata eve.json ──(tail, follows rotation)─┼─► Event ─► ATT&CK ─► Correlation ─► Dedup (SQLite) ─► Alert
Falco http_output ──(POST 127.0.0.1:2801)────┘                         │
                                                                       └─ findings from the last scan
```

- **Correlation with the scan**: an exploitation event (ATT&CK T1190) against a target that has a
  known vulnerability in the last report (e.g. PHP2Shell) becomes **Critical**, with the flaw cited.
- **Same IP in more than one source** within the window: severity goes up one level.
- **Target**: Falco reports the container; Suricata is mapped by the published destination port;
  CrowdSec reports the source IP and the scenario.
- **Deduplication**: key is source + rule + IP + target within `alerts.dedup_window`; repeats only
  increment the counter.
- The full scan runs every `scan.interval` inside `watch`.

### Notifications (stage 4)
- One *worker* and one queue per channel: a slow or down channel does not delay detection or the
  others.
- Up to 3 retries (2s, 8s, 30s). Errors never show the token embedded in the URL.
- Per-channel rate limit (token bucket): 10 burst + 1/min; **Critical has its own quota** (30 +
  1/min), so a flood of smaller alerts does not block it. On recovery, the channel receives
  "N alerts not sent".
- Attacker text treated as data on every channel: control and direction (bidi) characters removed;
  Telegram without `parse_mode`; Slack with `& < >` escaped (no `<!channel>`); Discord with empty
  `allowed_mentions` and no link preview; email with an encoded subject, no line break (no header
  injection) and mandatory TLS outside localhost; webhook signed with HMAC-SHA256 over
  `timestamp.body`.

### Administrator feedback (stage 4)
| Command | Effect |
|---------|--------|
| `feedback <id> fp` | creates a mute with an expiry (30 days). Default scope: the most restrictive (target, else IP, else rule) |
| `feedback <id> confirmed` | source IP marked hostile for 90 days: future events go up one level |
| `accept "<id>\|<target>" --reason` | risk accepted with a mandatory justification and an expiry (90 days); leaves the count and the alerts, shows up under "Accepted risks" in the report |

Everything expires — nothing stays silenced forever by forgetfulness. Silenced events are still
recorded (`[silenciado]` in `events`). **Safety net**: exploitation against a target with a known
vulnerability ignores any mute and the alert explains it.

The SQLite schema is versioned (`PRAGMA user_version`) and migrated automatically on open.

### AI, skills and vault (stage 5)

```
alert ──► log / notifiers (immediate)
   └────► Explainer (async, ≤2 at a time, per-hour cap) ──► Redactor ──► provider
                                                   response ──► SafeMarkdown ──► 2nd message,
                                                                memory (ai_note) and vault
```

- **Prompt** = the binary's fixed rules + skills selected by tags (≤ 14k characters) + task + data
  between `<dados>` (fake closings of the delimiter are neutralized).
- **Redactor**: secrets replaced; IPs/emails become stable pseudonyms per request; a private IP
  becomes `[IP-INTERNO-n]`, loopback `[IP-LOCAL]`. `ai.keep_ips: true` disables only the IP part.
- **SafeMarkdown** on the response: removes remote images (tracking pixel), HTML and embeds.
- **Providers**: Anthropic (Messages API), OpenAI and compatibles (chat completions —
  `max_completion_tokens` on OpenAI, `max_tokens` on the others), Gemini (`generateContent`, key in
  a header). `http://` only for localhost.
- **Vault**: `Início.md`, `Relatórios/`, `Ativos/`, `Incidentes/`, `Técnicas/`. Atomic writes,
  sanitized file names restricted to the vault directory. Log text always in a code block with a
  fence longer than any backtick run in the content. The part after `<!-- sentinels:notas -->`
  belongs to the administrator and is preserved.

### Scan alert volume (stage 6)
- First scan (no history in memory) = baseline: **one** summary.
- After that: an individual alert for a new configuration finding, a CVE in KEV or an emergency
  alert (max 10 per scan, the rest summarized); other new CVEs grouped by target.
- CVEs of kernel packages inside the images are discarded (containers use the host's kernel) and
  counted in the report. In a test with `php:8.3.10-apache`: 1,267 of 1,536 CVEs were kernel ones;
  the first scan went from 1,537 alerts to 1.

### Deployment (stage 6)
- **Docker**: distroless `static-debian13:nonroot` + Trivy, user 65532, read-only rootfs, no
  capabilities; Docker API via `docker-socket-proxy` (only GET of containers and images).
  `DOCKER_HOST` is honored.
- **systemd**: dedicated user, sandbox (`systemd-analyze security` 1.7), writes only to
  `/var/lib/sentinels`.
- **Release**: amd64/arm64 binaries + `checksums.txt`; `install.sh` verifies the SHA-256.

### Read-only
The agent reads the Docker API and log files. No blocking action in v1 — it avoids a false positive
taking production down. Blocking is left to the CrowdSec bouncer, if the user wants it.

### Row-Level Security check (PostgreSQL)
With a read-only connection given in the configuration, the agent queries the catalog:

- tables with a tenant column (`org_id`, `organization_id`, `tenant_id`, `school_id`…) and
  `relrowsecurity = false` → **Critical**;
- RLS enabled without `relforcerowsecurity` and the application connecting as owner → **High**
  (the owner bypasses the policies);
- the application role has `SUPERUSER` or `BYPASSRLS` → **Critical**;
- a table with RLS enabled and no policy → **Medium** (blocks everything; likely a mistake).

The report's recommendations follow the correct practices: `set_config('app.org_id', $1, true)`
inside a transaction (equivalent to `SET LOCAL`), never string interpolation, and
`FORCE ROW LEVEL SECURITY` on the multitenant tables.

## Configuration

File: `/etc/sentinels/sentinels.yaml` (example in `sentinels.example.yaml`).
Secrets (AI key, notification tokens, database DSN) always via environment variables.

## Running

- **systemd**: binary in `/usr/local/bin/sentinels`, dedicated user `sentinels` in the `docker`
  group (socket read access).
- **Docker**: socket mounted as `:ro`, read-only filesystem.

## Out of scope (v1)
- Automatic blocking of IPs or containers.
- Own packet capture (left to Suricata).
- Web dashboard.
