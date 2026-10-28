# Talking to the agent on Telegram

Besides receiving alerts, you can query the agent and respond to alerts from the chat.

## Enable

`sentinels setup` → **Notifications**:
- a new Telegram channel: answer "Yes" to *"Conversar com o agente por este chat?"*;
- an existing channel: choose **💬 ativar conversa**.

Save and restart the agent (Portainer: Update the service / Restart). In the chat, send `/help`.

## What you can do

| In the chat | Response |
|-------------|----------|
| `/status` | last scan, open criticals, events in the last 24 h (if the first scan is still running, it says so and sends the status when it finishes) |
| `/blocked` · `/bloqueados` · `/blocked 13.140` · `/blocked ssh` | IPs blocked right now by CrowdSec (detections from this server and manual bans), scenario, time left and how many events the IP generated in 30 days. The CrowdSec community list is not included. Unblocking is still done over SSH: `sudo cscli decisions delete --ip IP` |
| `/metrics` · `/metricas` | mean time to fix (MTTR), criticals open for more than 7 days, false-positive rate, top attacking IPs and most-seen ATT&CK techniques |
| `/report` · `/relatorio` · `/report hoje` | summary of the previous day (or of today so far): total and severity, **countries the attacks came from the most**, most active IPs and the **attack type** (ATT&CK technique). Same content as the automatic daily report |
| `/update` · `/atualizar` | checks on GitHub whether a newer version exists and shows the command to update. It does **not** update on its own — the bot only queries |
| `/doctor` | what Sentinels has active (Docker, Trivy, CrowdSec, Suricata, Falco, AI, channels) and the exact commands to install what is missing — you run them over SSH |
| `/inventory` · `/inventory php` | what is running: containers, image, stack, public ports and the problems of each (packages installed directly on the system are not included) |
| `/scan` | confirms right away ("Em poucos minutos te mando o status"), runs a full scan and sends the status when it finishes |
| `/findings` · `/findings critical` · `/findings all` | open problems |
| `/events` · `/events 72` | recent attacks and events, numbered |
| `/event 12` | event detail, the AI analysis and buttons |
| `/muted` | active false-positive rules |
| Buttons on alerts | **✅ Ataque real** · **🔕 Falso positivo** · **🤖 Explicar** |
| Any question | answered by the configured AI, e.g. *"o que aconteceu hoje?"*, *"o PHP da loja está vulnerável?"* |

Anything slow replies right away with a confirmation — "🤔 Analisando sua pergunta…",
"🤖 Analisando o evento #12…", "🔎 Iniciando uma varredura…" — and the full answer arrives next.

The Portuguese names from earlier versions (`/varrer`, `/achados`, `/eventos`, `/evento`,
`/silenciados`, `/ajuda`) still work.

The buttons do the same as `sentinels feedback` in the terminal: a false positive silences identical
events for 30 days (except exploitation against a vulnerable target); a real attack makes the IP
weigh more in the next alerts for 90 days.

## Security

- **Only the configured chat is served.** Messages and buttons coming from any other chat are
  ignored (and logged once). In a group, every member of the group can use the bot — use a group
  that is just the team.
- **Nothing is changed on the server.** The bot queries data and records feedback; it does not
  restart containers, block IPs or run commands.
- **No open port.** The agent fetches the messages from Telegram (long polling).
- **Old messages are ignored**: whatever arrived while the agent was down is not answered.
- Plain-text responses (no formatting), masked secrets; questions to the AI use the same redaction
  as the alerts (`[IP-1]`…) and count toward the `ai.max_calls_per_hour` limit.

## Several servers

Telegram allows **a single reader per bot**. With more than one agent (several servers or a Swarm
with several nodes), create **one bot per server** for the chat — the same group can receive the
alerts from all of them. If two agents read the same bot, the log shows
*"outro processo está lendo este bot"*.

## Why the bot installs nothing

Installing CrowdSec, Suricata or Falco requires root on the server. If the bot could do that, anyone
who took over your Telegram account — or managed to inject text the AI would obey — would gain root
on the VPS with a single message. That is why `/doctor` shows what is missing and the ready-made
commands, and you are the one who runs them, over SSH. The agent stays read-only.
