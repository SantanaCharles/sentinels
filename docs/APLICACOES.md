# Dentro das aplicações e dos bancos de dados

Como o Sentinels observa o que acontece **dentro** de uma aplicação e do banco dela — inclusive
quando quem ataca é um usuário logado.

A rede sozinha não basta: a conexão app → banco costuma ter TLS, e um usuário logado manda
consultas que saem do mesmo usuário de banco que a aplicação usa. Com ORM (Prisma, Eloquent,
TypeORM…), SQL injection é raro; o ataque típico de quem está logado é **IDOR** — trocar o ID na
URL para ver o dado de outro cliente. Por isso são quatro camadas, cada uma vendo uma parte.

| Camada | Pega | Precisa de |
|--------|------|------------|
| 1. Logs do banco e da aplicação | SQL injection (com a consulta no alerta), rajada de erros de SQL, violação de RLS, acesso negado, comandos perigosos, força bruta de senha no banco, enumeração de IDs (IDOR), força bruta no login | nada (vem ligado) |
| 2. Quem conversa com o banco | container novo ou IP da internet conectando no banco | `/proc` do host montado (já vem nos arquivos de `deploy/`) |
| 3. Dentro dos containers (Falco) | banco ou PHP abrindo shell, webshell gravado, banco conectando para fora, ferramentas de ataque, minerador, instalação de pacote | Falco + regras do Sentinels |
| 4. Na porta, antes da aplicação (WAF) | exploits de CVEs conhecidos bloqueados na hora; SQLi/XSS genéricos → ban do IP | CrowdSec + plugin no Traefik |

As camadas 3 e 4 são instaladas por `sudo sentinels setup install`, com cada comando mostrado e
confirmado antes.

## 1. Logs do banco e da aplicação

O agente lê pela API do Docker (só leitura, pelo socket-proxy) o log dos containers de
**PostgreSQL** e das **aplicações**. Proxies reversos ficam com o CrowdSec. Nada é lido do disco
das aplicações nem das tabelas do banco.

**PostgreSQL** — com a configuração padrão da imagem oficial, toda consulta que dá erro aparece no
log com o texto da consulta. O agente alerta:

| Regra | Quando | Nível |
|-------|--------|-------|
| `postgres-sqli-attempt` | consulta que falhou contendo `UNION SELECT`, `information_schema`, `pg_shadow`, `' OR '1'='1`, comando empilhado (`; DROP`), `pg_sleep`… | Crítico |
| `postgres-dangerous-command` | `COPY … PROGRAM`, `pg_read_file`, `lo_import`, `dblink`, `ALTER SYSTEM`, função em C/linguagem não confiável | Crítico |
| `postgres-sql-error-burst` | 5 erros de sintaxe em 5 min (padrão de quem testa injeção) | Alto |
| `postgres-rls-violation` | `new row violates row-level security policy` (gravar dado de outro tenant) | Alto |
| `postgres-permission-denied` | acesso negado a tabela/função; 10 em 5 min sobe para Alto | Médio |
| `postgres-auth-bruteforce` | 5 senhas erradas em 5 min | Alto |
| `postgres-external-connection` | `no pg_hba.conf entry` vindo de IP da internet | Alto |

Um erro comum da aplicação (coluna que não existe, por exemplo) **não** vira alerta: só erros com
cara de ataque, ou em rajada.

Para pegar SQL injection **por tempo** (`pg_sleep(5)`), ligue o log de consultas lentas no
Postgres — no `command` do serviço:

```yaml
command: ["postgres", "-c", "log_min_duration_statement=3000"]
```

**MySQL/MariaDB** não registram consultas com erro por padrão; para eles valem os logs da
aplicação (abaixo), as camadas 2 a 4 e o Falco.

**Aplicação** — o agente entende o formato de acesso do Apache/Nginx (imagens PHP) e logs em JSON
(pino, winston, Laravel com canal `stderr` em JSON…):

| Regra | Quando | Nível |
|-------|--------|-------|
| `app-sqli-attempt` | erro de SQL no log (`SQLSTATE[`, `You have an error in your SQL syntax`, `QueryFailedError`…) com trecho de injeção | Crítico |
| `app-sql-error-burst` | 5 erros de SQL em 5 min | Alto |
| `app-enumeration` | o mesmo usuário (ou IP) recebe 30 respostas 403/404 em 10+ endereços diferentes em 5 min — percorrendo IDs | Alto com usuário logado, Médio só com IP |
| `app-login-bruteforce` | 20 respostas 401 em 5 min | Alto |

Para a detecção de IDOR funcionar, **o log da aplicação precisa dizer quem fez a requisição**.
Exemplo de linha que o agente entende (Node com pino):

```json
{"req":{"method":"GET","url":"/api/pedidos/1042"},"res":{"statusCode":403},"userId":"u-77"}
```

Campos reconhecidos: status em `status`/`statusCode`/`status_code`; usuário em
`userId`/`user_id`/`uid`/`user`/`username`/`sub`/`email` (ou `user.id`); IP em
`ip`/`client_ip`/`remoteAddr`/`remoteAddress`; caminho em `path`/`url`/`uri`. Atrás do Traefik,
sem usuário nem IP real no log, a aplicação não tem como distinguir quem é quem — essas linhas são
ignoradas.

Aplicações que não registram as requisições (muitas em Next.js) continuam cobertas pelos erros
de SQL, pelo RLS e pelas outras camadas.

## 2. Quem conversa com o banco

A cada minuto o agente lê a tabela de conexões do container de cada banco (Postgres, MySQL,
Mongo, Redis…) em `/proc/<pid>/net/tcp`, sem senha e sem tocar no banco:

- nos primeiros 30 minutos (ou até o primeiro cliente aparecer) ele **aprende** quem conecta —
  normalmente só a aplicação;
- depois, um cliente novo vira alerta Médio `db-new-client`: "Novo cliente conectando no banco
  erp-db: estranho. Até agora só conectavam: erp-app";
- conexão vinda **da internet** vira `db-external-client` (Alto) sempre, mesmo no aprendizado.

Os clientes são identificados pelo serviço do Compose ou do Swarm, que não muda quando o
container é recriado. A linha de base fica em `/var/lib/sentinels/db-clients.json`; apague o
arquivo para reaprender do zero.

No Docker, o agente precisa do `/proc` do host, já presente nos arquivos de `deploy/`:

```yaml
    volumes:
      - /proc:/host/proc:ro
```

O container continua sem root e sem capabilities; ele só passa a **ver** os processos do host.
Na instalação via systemd nada muda.

## 3. Dentro dos containers (Falco)

O `setup install` → Falco grava `/etc/falco/rules.d/sentinels.yaml` e liga `rule_matching: all`
em `/etc/falco/config.d/sentinels.yaml`. Sem essa opção a primeira regra que casa com o evento
"ganha" — e a regra padrão do Falco para shell aberto por banco tem prioridade baixa (Notice).

| Regra | Nível |
|-------|-------|
| Banco abriu um shell (`COPY … TO PROGRAM`, função maliciosa, Redis explorado) | Crítico |
| PHP abriu um shell (RCE, webshell, PHP2Shell) — o `mail()` é ignorado | Crítico |
| Servidor web gravou `.php`/`.phtml`/`.phar`/`.jsp` no site (webshell) | Médio |
| Banco conectou para a internet (extração, shell reverso) | Crítico |
| Ferramenta de ataque no container (`nmap`, `sqlmap`, `hydra`, `chisel`…) | Crítico |
| Minerador de criptomoeda | Crítico |
| Instalação de pacote com o container rodando | Médio |
| Aplicação Node/Python/Ruby/Java abriu um shell | Médio |

O Falco é o que pega o ataque que **deu certo** — um `COPY … TO PROGRAM` executado por um
usuário com privilégio não gera erro no log do banco, mas abre um shell.

Ajustes locais vão em `/etc/falco/rules.d/sentinels-local.yaml` (reinstalar sobrescreve o
`sentinels.yaml`). Para silenciar um alerta específico, use 🔕 Falso positivo no Telegram.

## 4. WAF do CrowdSec no Traefik

O `setup install` → CrowdSec, quando encontra o Traefik, oferece ativar o **AppSec**:

1. instala as regras `appsec-virtual-patching`, `appsec-generic-rules` e `appsec-crs` (OWASP CRS);
2. liga o componente em `IP-da-docker0:7422` — alcançável pelos containers, não pela internet;
3. cria a chave `traefik-appsec` e mostra os argumentos e labels para colar na stack do Traefik
   (plugin `crowdsec-bouncer-traefik-plugin` fixado na v1.7.1). O Sentinels não edita o Traefik:
   um erro ali derruba todos os sites.

Como funciona, testado com o CrowdSec real:

- exploits de CVEs conhecidos e acesso a `/.env` são **bloqueados na hora** (403);
- SQL injection, XSS e path traversal genéricos (OWASP CRS) **não** bloqueiam a requisição, para
  não barrar usuário legítimo por engano. Depois de algumas tentativas o IP é **banido**
  (`crowdsec-appsec-outofband`) e o alerta chega no Telegram;
- se o CrowdSec cair, os sites continuam no ar (`crowdsecappsecunreachableblock=false`).

## Testar (no seu servidor)

| Camada | Como | Esperado |
|--------|------|----------|
| 1 | `docker exec <container-do-postgres> psql -U <usuario> -c "SELECT 1 UNION SELECT usename, passwd FROM pg_shadow--"` | `[CRÍTICO] postgres-sqli-attempt` com a consulta |
| 1 | o mesmo comando 5 vezes com `"SELECT * FROM x WHERE a = 'o'brien'"` | `[ALTO] postgres-sql-error-burst` |
| 2 | `docker run --rm --network <rede-do-banco> postgres:17-alpine pg_isready -h <servico-do-banco>` depois de 30 min de agente rodando | `[MÉDIO] db-new-client` em `/events` |
| 3 | `docker run --rm php:8.3-cli-alpine php -r 'echo shell_exec("id");'` | `[CRÍTICO] Sentinels PHP spawned shell` |
| 4 | de outra rede: `curl -s -o /dev/null -w '%{http_code}' https://SEU-SITE/.env` | `403` |

## Privacidade

- Só as linhas que viram alerta são guardadas, cortadas em ~240 caracteres. O resto do log é
  lido e descartado.
- Antes de qualquer envio para a IA, segredos são mascarados e IPs/e-mails pseudonimizados.
- Para tirar um container da leitura de logs: `integrations.containers.exclude: [nome]`. Para
  desligar uma parte: `logs: false` ou `db_clients: false`.
