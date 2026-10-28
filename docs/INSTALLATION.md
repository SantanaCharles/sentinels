# Installation

Two ways, same functionality. When in doubt, use **Docker**: it is the most isolated.

## Option A — Docker Compose (recommended)

```bash
git clone https://github.com/SantanaCharles/sentinels && cd sentinels/deploy
cp sentinels.docker.yaml sentinels.yaml
cp sentinels.env.example sentinels.env && chmod 600 sentinels.env
docker compose up -d
docker compose exec sentinels sentinels doctor -config /etc/sentinels/sentinels.yaml
docker compose logs -f sentinels
```

- The image already ships with **Trivy**.
- The agent **does not get the Docker socket**: it uses `tecnativa/docker-socket-proxy`, which only
  allows reading containers and images (any `POST` gets a 403). Even if compromised, the agent
  cannot create containers or control the host.
- Runs as user 65532, read-only filesystem, no capabilities, with `no-new-privileges` and a memory
  limit.
- `network_mode: host` is needed to test the ports published on `127.0.0.1`, see services listening
  on the host and receive Falco on `127.0.0.1:2801`.
- Commands: `docker compose exec sentinels sentinels <command> -config /etc/sentinels/sentinels.yaml`.
- Setup wizard (writes `sentinels.yaml` and `sentinels.env` in this folder):

  ```bash
  docker run --rm -it --network host --user "$(id -u):$(id -g)" -v "$PWD:/work" \
    ghcr.io/santanacharles/sentinels:latest setup -config /work/sentinels.yaml -env /work/sentinels.env
  ```

  Then, as a separate command (recreates the container: `restart` does not re-read `sentinels.env`):

  ```bash
  docker compose up -d --force-recreate sentinels
  ```

### Install CrowdSec, Suricata and Falco (Docker or Portainer)

These components run on the host, so also install the `sentinels` command on the VPS (the CLI only,
no service — the agent stays in Docker):

```bash
curl -fsSL https://github.com/SantanaCharles/sentinels/releases/latest/download/install.sh -o install.sh
sudo sh install.sh --cli-only
cd ~/sentinels/deploy && sudo sentinels setup install
```

The wizard finds the `sentinels.yaml` in the current folder, shows every command before running it,
writes the CrowdSec key to `sentinels.env`, enables the Suricata log in `docker-compose.yml` and,
on save, offers to recreate the Sentinels container.

## Option A2 — Portainer (stack)

1. **Stacks → Add stack**, name `sentinels`, **Web editor**: paste the file that matches your
   environment → **Deploy the stack**.

   | Portainer environment | File |
   |-----------------------|------|
   | Docker Standalone | [`deploy/portainer-stack.yml`](../deploy/portainer-stack.yml) |
   | **Docker Swarm** (common on VPSes with Traefik, n8n, Evolution API) | [`deploy/portainer-stack-swarm.yml`](../deploy/portainer-stack-swarm.yml) |

   If you see *"Compose file contains unsupported options: mem_limit"*, the environment is Swarm:
   use the second file. In it the agent and proxy run in **global** mode (one per node), on the
   host network, and the proxy listens only on `127.0.0.1` — on Swarm do not use `ports` for the
   proxy, because Swarm ignores the `127.0.0.1` and would publish the port on every interface.
   (You can also use **Repository**: URL `https://github.com/SantanaCharles/sentinels` and the
   file path — updates with "Pull and redeploy".)
2. **Containers → sentinels-sentinels-1 → Console** → *Command*: **Custom** →
   `/usr/local/bin/sentinels setup -config /var/lib/sentinels/sentinels.yaml` → leave *User*
   empty → **Connect**. Configure it with the arrow keys and choose "Save and exit". If the menu is
   slow to appear, use the same command with `--plain` (simple questions).
3. **Restart** the `sentinels-sentinels-1` container (Swarm: **Services → sentinels_sentinels →
   Update the service** with "Re-pull image" unchecked) and follow along in **Logs**.

No files on the host: `sentinels.yaml` and `sentinels.env` (0600) live in the `sentinels-data`
volume, and the agent reads the `.env` on its own. Before step 2 it already runs with the default
configuration (scan, CVEs, leaked keys; alerts only in the log).

Portainer itself will show up in the report: it mounts the Docker socket with write access
(Critical) and publishes the panel (High). That is expected for Portainer — keep it updated, with a
strong password / 2FA and, preferably, reachable only over VPN or an SSH tunnel.

## Option B — Binary + systemd

```bash
curl -fsSL https://github.com/SantanaCharles/sentinels/releases/latest/download/install.sh -o install.sh
less install.sh                     # read it before running as root
sudo sh install.sh
sudo nano /etc/sentinels/sentinels.yaml
sudo nano /etc/sentinels/sentinels.env
sudo -u sentinels sentinels doctor -config /etc/sentinels/sentinels.yaml
sudo systemctl enable --now sentinels
journalctl -u sentinels -f
```

At the end, the installer offers to open the **wizard** (`sentinels setup`) — it works even with
`curl … | sudo sh`, because it reads from the terminal. Skip it with `--no-setup`. In some
providers' web consoles the menu can take ~5 s to open (the console does not answer terminal
queries); `sentinels setup --plain` uses simple questions.

The installer:
- checks the **SHA-256** of each file against the release's `checksums.txt` and installs nothing if
  anything does not match;
- creates the `sentinels` system user and adds it only to the groups that exist (`docker`, `adm`,
  `systemd-journal`);
- **does not overwrite** an existing `sentinels.yaml` or `sentinels.env`; `sentinels.env` is 0600
  (root only — systemd reads it before switching user);
- **does not start** the service (use `--start` if you want it to).

The service runs under the systemd sandbox (`ProtectSystem=strict`, no capabilities, syscall filter,
writes only to `/var/lib/sentinels`): `systemd-analyze security sentinels` → **1.7 OK**.

**Heads up:** being in the `docker` group is equivalent to root on the host. To isolate it like
Docker Compose does, bring up only the proxy and point the agent at it:

```bash
docker run -d --name sentinels-socket-proxy --restart unless-stopped \
  -e CONTAINERS=1 -e IMAGES=1 -e SERVICES=1 -e POST=0 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro -p 127.0.0.1:2375:2375 \
  --label io.sentinels.self=true tecnativa/docker-socket-proxy:v0.5.0
sudo gpasswd -d sentinels docker
echo 'DOCKER_HOST=tcp://127.0.0.1:2375' | sudo tee -a /etc/sentinels/sentinels.env
sudo systemctl restart sentinels
```

Verify, upgrade, test detection and troubleshoot: [OPERATIONS.md](OPERATIONS.md).

Upgrade: run `install.sh` again. Remove: `sudo sh install.sh --uninstall`
(`--purge` also deletes configuration, memory and the user).

### Trivy (image CVEs)

```bash
# https://trivy.dev/latest/getting-started/installation/
sudo apt install trivy          # after adding the official repository
```

## First run

The first scan is the **baseline**: you get a single summary, not one alert per finding. From then
on only new things arrive — and common CVEs are grouped by container; only actively exploited CVEs
(CISA KEV) and emergency alerts come in one by one.

CVEs of kernel packages inside the images (`linux-libc-dev`…) are ignored: the container uses the
host's kernel. Keep the server's kernel updated.

## Emergency alert feed (maintainers)

`internal/intel/advisories.json` is signed with Ed25519. After editing it:

```bash
go run ./cmd/feedsign sign -key ~/.sentinels/feed-signing.key internal/intel/advisories.json
go run ./cmd/feedsign verify internal/intel/advisories.json
git add internal/intel/advisories.json internal/intel/advisories.json.sig
```

CI fails if the signature does not check out. The private key never goes into the repository
(`*.key` is in `.gitignore`).

### AI draft

```bash
go run ./cmd/feedsign draft -in https://www.cisa.gov/news-events/alerts/... -config sentinels.yaml -out draft.json
```

The AI reads the advisory and proposes the feed entry. The draft is validated: the format of each
field, and **every CVE, fixed version and URL must appear in the source text** (catches AI
inventions); products the agent does not yet detect are flagged. Nothing is added to the feed or
signed automatically — review it, paste it into `advisories.json` and run `feedsign sign`.
