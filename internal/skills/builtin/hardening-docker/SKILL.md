---
name: hardening-docker
description: Boas práticas de segurança para containers Docker e docker-compose, alinhadas ao CIS Docker Benchmark.
metadata:
  applies-to: "container.*, exposure.*, t1611, task:report"
---

# Hardening de containers (CIS Docker Benchmark)

## Prioridades (do mais grave ao menos)
1. **Nunca `privileged: true`** (CIS 5.5) e nunca montar `/var/run/docker.sock` (CIS 5.32) —
   ambos equivalem a dar root no host. Se um proxy reverso precisa do socket, use
   `tecnativa/docker-socket-proxy` liberando só leitura de containers.
2. **Bancos, caches e painéis só em rede interna** (CIS 5.14): no compose, prefira não publicar
   a porta (`expose` ou nenhuma) e conectar os serviços pela rede do Docker. Se precisar
   publicar, use `"127.0.0.1:5432:5432"`. Atenção: o Docker escreve regras de iptables próprias e
   **ignora o UFW** para portas publicadas — firewall do host não protege `0.0.0.0:porta`.
3. **Sem montar diretórios sensíveis do host** (`/`, `/etc`, `/root`, `/var/lib/docker`) (CIS 5.6).
4. **Usuário sem privilégio** (CIS 4.1): `USER app` no Dockerfile ou `user: "1000:1000"`.
5. **Capacidades mínimas** (CIS 5.4): `cap_drop: [ALL]` e adicione só o necessário.
6. `security_opt: ["no-new-privileges:true"]` (CIS 5.26).
7. **Limites de recursos** (CIS 5.11): `mem_limit`, `cpus`, `pids_limit`.
8. `read_only: true` com `tmpfs` para diretórios de escrita, quando a aplicação permitir.

## Exemplo de serviço endurecido
```yaml
services:
  app:
    image: minha-app:1.4.2          # tag fixa, nunca :latest em produção
    user: "1000:1000"
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 512m
    pids_limit: 200
    networks: [interna]
  db:
    image: postgres:16
    # sem "ports:" — só a app alcança o banco pela rede interna
    networks: [interna]
networks:
  interna: {}
```

## Imagens e segredos
- Atualize imagens base regularmente e reconstrua; fixe tags com versão.
- Segredos em `environment` aparecem em `docker inspect`: prefira `secrets:` ou arquivos com
  permissão restrita e a variável `*_FILE` (suportada pelas imagens oficiais).
