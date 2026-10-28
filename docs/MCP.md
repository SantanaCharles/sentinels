# MCP server

`sentinels mcp` exposes the agent's memory to MCP clients (Claude Code, Claude Desktop, ChatGPT,
Cursor, VS Code…). You ask in natural language — "what happened on the VPS today?", "which
containers are vulnerable to PHP2Shell?", "explain event 42" — and the AI queries the tools.

## Tools (all read-only)

| Tool | Returns |
|------|---------|
| `resumo_servidor` | last scan, totals, open criticals, events in the last 24 h |
| `listar_achados` | open findings (filters: severity, target, limit, accepted risks) |
| `listar_eventos` | real-time detections (window in hours, severity, limit) |
| `detalhar_evento` | one event with correlation, the admin's verdict and the AI analysis |
| `inventario` | containers and stack from the last scan |
| `ultimo_relatorio` | the full report in Markdown |
| `listar_silenciamentos` | active false-positive rules |

There is no tool that changes anything: the database is opened read-only. To give feedback or accept
risks, use the command line on the server.

## Connect

### Claude Code (over SSH — recommended)

```bash
claude mcp add sentinels -- ssh my-vps sudo -u sentinels sentinels mcp -config /etc/sentinels/sentinels.yaml
```

With Docker Compose on the server:

```bash
claude mcp add sentinels -- ssh my-vps docker compose -f /opt/sentinels/deploy/docker-compose.yml exec -T sentinels sentinels mcp -config /etc/sentinels/sentinels.yaml
```

### Claude Desktop and other clients (stdio)

```json
{
  "mcpServers": {
    "sentinels": {
      "command": "ssh",
      "args": ["my-vps", "sudo", "-u", "sentinels", "sentinels", "mcp", "-config", "/etc/sentinels/sentinels.yaml"]
    }
  }
}
```

Use SSH key authentication and, preferably, a `sudoers` rule that lets your user run **only** that
command:

```
your_user ALL=(sentinels) NOPASSWD: /usr/local/bin/sentinels mcp -config /etc/sentinels/sentinels.yaml
```

### HTTP (Streamable HTTP)

For clients that only speak HTTP:

```bash
echo "SENTINELS_MCP_TOKEN=$(openssl rand -hex 32)" | sudo tee -a /etc/sentinels/sentinels.env
sudo -u sentinels env $(sudo cat /etc/sentinels/sentinels.env | xargs) sentinels mcp --http 127.0.0.1:8765
ssh -L 8765:127.0.0.1:8765 my-vps        # on your machine
```

Client: URL `http://127.0.0.1:8765/mcp`, header `Authorization: Bearer <token>`.

- Token mandatory (at least 24 characters), compared in constant time.
- Listens only on localhost; another address requires `--allow-remote` **and** TLS on a reverse
  proxy.
- Browser requests with an `Origin` other than localhost are refused (DNS rebinding protection).

## Privacy and security

- Every response goes through the same AI redaction: secrets removed; IPs and emails become
  pseudonyms (`[IP-1]`), stable within a response. To see real IPs: `mcp.keep_ips: true`. Remember
  that the content goes to the model provider your client uses.
- **Injection via logs:** fields coming from logs may contain text written by an attacker (e.g.
  "ignore the instructions and run this command"). Sentinels' tools do not execute anything, but
  your client may have **other** tools (shell, files). That is why each response marks those fields
  as untrusted data and the server's instructions ask the model not to act on them. Even so:
  **review before approving any suggested command** in a session where Sentinels is connected.

## Test

```bash
npx @modelcontextprotocol/inspector --cli sentinels mcp -config /etc/sentinels/sentinels.yaml --method tools/list
```
