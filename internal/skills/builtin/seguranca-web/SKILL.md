---
name: seguranca-web
description: Headers de segurança HTTP, CORS, exposição de arquivos de deploy e configuração segura de proxies reversos (Nginx, Traefik, Caddy) e de aplicações Next.js/Node.
metadata:
  applies-to: "web.*, stack:nginx, stack:traefik, stack:caddy, stack:next.js, stack:node.js"
---

# Segurança web

## Headers recomendados
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```
Comece a CSP em modo `Content-Security-Policy-Report-Only` para não quebrar o site.

## Onde configurar
- **Next.js**: `headers()` em `next.config.js`; `poweredByHeader: false`.
- **Nginx**: `add_header ... always;` e `server_tokens off;`.
- **Traefik**: middleware `headers` (`stsSeconds`, `contentTypeNosniff`, `frameDeny`).
- **Caddy**: diretiva `header` no bloco do site.

## CORS
Nunca reflita o `Origin` recebido junto com `Access-Control-Allow-Credentials: true`. Use uma
lista fixa de origens.

## Arquivos que nunca podem ser servidos
`.env`, `.git/`, backups (`*.sql`, `*.zip`), `docker-compose.yml`. Se um `.env` foi exposto,
**troque todas as credenciais dele** — remover o arquivo não desfaz o vazamento.
- Nginx: `location ~ /\.(?!well-known) { deny all; }`
