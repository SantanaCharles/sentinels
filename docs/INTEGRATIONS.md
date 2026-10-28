# Real-time integrations

`sentinels watch` has no attack signatures of its own: it reads the engines below, all free and
maintained by large communities. Install the ones that make sense; each is optional and
`sentinels doctor` shows what was found.

| Engine | Sees | Best for |
|--------|------|----------|
| [CrowdSec](https://crowdsec.net) | logs (Nginx, Traefik, Caddy, SSH…) | web attacks and brute force, IP reputation |
| [Suricata](https://suricata.io) | network traffic | scans, protocol exploitation, C2 |
| [Falco](https://falco.org) | container system calls | what happens **after** a breach: shell, writes to sensitive directories, mining |

If you install only one: **CrowdSec**. For production containers, add **Falco**.

Without installing anything, the agent also reads the Postgres and application logs and watches who
connects to each database: see [APPLICATIONS.md](APPLICATIONS.md), which also explains the Falco rules
and the CrowdSec WAF installed by `setup install`.

## Easiest way: `sentinels setup install`

```bash
sudo sentinels setup install          # on a Docker install: cd ~/sentinels/deploy first
```

The wizard installs and configures each engine, showing the commands and asking for confirmation:
CrowdSec (Sentinels key, proxy logs in a container, port 8080, firewall blocking with `DOCKER-USER`
and your IP whitelisted), Suricata (interface, rules, volume in the compose) and Falco (modern
driver and alert delivery). On a Docker/Portainer install, first install just the command on the
host: `sudo sh install.sh --cli-only`.

The sections below describe the **manual** install, for other distributions or for those who prefer
to do it by hand. To test detection afterwards, see
[OPERATIONS.md](OPERATIONS.md#3-test-detection-simulated-attacks).

## CrowdSec

```bash
curl -s https://install.crowdsec.net | sudo sh
sudo apt install crowdsec
sudo cscli collections install crowdsecurity/nginx crowdsecurity/linux   # adjust to your stack
sudo cscli bouncers add sentinels          # copy the key shown
```

`/etc/sentinels/sentinels.env`:
```
SENTINELS_CROWDSEC_KEY=<key>
```

Sentinels reads only the decisions generated **on this server** (origin `crowdsec`/`cscli`); the
community list (CAPI) is ignored to avoid thousands of alerts. For CrowdSec to also block, install a
bouncer (e.g. `crowdsec-firewall-bouncer-iptables`) — Sentinels does not block.

### CrowdSec WAF (AppSec) with Traefik

`setup install` offers to enable it when it finds Traefik. Manually:

```bash
sudo cscli collections install crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules crowdsecurity/appsec-crs
ip -4 addr show docker0          # e.g. 172.17.0.1
sudo tee /etc/crowdsec/acquis.d/sentinels-appsec.yaml <<'EOF'
appsec_configs:
  - crowdsecurity/appsec-default
  - crowdsecurity/crs
labels:
  type: appsec
listen_addr: 172.17.0.1:7422
source: appsec
EOF
sudo systemctl reload crowdsec
sudo cscli bouncers add traefik-appsec      # key for the Traefik plugin
```

Traefik configuration and behavior: [APPLICATIONS.md](APPLICATIONS.md#4-crowdsec-waf-on-traefik).

## Suricata

```bash
sudo apt install suricata
sudo suricata-update                         # downloads the ET Open rules
sudo systemctl enable --now suricata
```

Check in `/etc/suricata/suricata.yaml` that `eve-log` is enabled with `- alert`. Sentinels follows
`/var/log/suricata/eve.json` (including after logrotate) and uses the rules' `mitre_technique_id`
when present. Update the rules daily (`suricata-update` via cron or a timer).

## Falco

```bash
# see https://falco.org/docs/setup/packages/
sudo apt install falco
```

In `/etc/falco/falco.yaml`:
```yaml
json_output: true
http_output:
  enabled: true
  url: "http://127.0.0.1:2801/falco"
```

The Sentinels receiver accepts only `127.0.0.1`/`::1`: any process that reaches that port can inject
events, so it must never be exposed.

`sentinels setup install` writes this to `/etc/falco/config.d/sentinels.yaml` (with
`rule_matching: all`) and installs the Sentinels rules for apps and databases in
`/etc/falco/rules.d/sentinels.yaml` — details in
[APPLICATIONS.md](APPLICATIONS.md#3-inside-the-containers-falco).

## How events are handled

1. **Classification** with MITRE ATT&CK (the rule's explicit ID when present, otherwise by name).
2. **Target**: Falco's container; for Suricata, the container owning the destination port.
3. **Correlation**:
   - exploitation (T1190, T1059, T1505.003, T1068, T1611, T1133) against a target with a known
     vulnerability in the last scan → **Critical**, citing the flaw;
   - the same IP seen by another engine in the last hour → severity goes up one level.
4. **Deduplication** within the `alerts.dedup_window`: repeats only increment the counter.
5. **Alert** from `alerts.min_severity` on. Everything stays in local memory
   (`sentinels events --since 24h --min low`).
