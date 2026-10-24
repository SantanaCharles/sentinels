# Arquitetura do Sentinels

## Visão geral

```
                    ┌──────────────────────── Servidor / VPS ────────────────────────┐
                    │                                                                │
  Docker Engine ───►│  Discovery ──► Fingerprint ──► Checks ──┐                      │
  (somente leitura) │                                         ▼                      │
                    │                                    Findings ──► Report (MD/JSON)│
  Trivy ───────────►│  Integrations ─────────────────────────▲                      │
                    │                                         │                      │
  CrowdSec ────────►│                                         │                      │
  Suricata (eve) ──►│  Watch (eventos) ──► Correlação ──► Alert ──► Notifiers ──────┼──► Telegram/Slack/
  Falco ───────────►│                                         │                      │    Discord/E-mail/Webhook
                    │                                         ▼                      │
                    │                                  AI (opcional, assíncrona) ────┼──► Claude/GPT/Gemini/
                    │                                                                │    OpenRouter/Ollama
                    └────────────────────────────────────────────────────────────────┘
```

## Módulos

| Pacote | Responsabilidade |
|--------|------------------|
| `cmd/sentinels` | CLI: `scan`, `watch`, `doctor`, `version` |
| `internal/config` | Carrega `sentinels.yaml` e variáveis de ambiente |
| `internal/discovery` | Lista containers via API do Docker (socket Unix, somente leitura) e portas em escuta |
| `internal/fingerprint` | Identifica a stack: imagem, portas, headers HTTP, labels |
| `internal/checks` | Verificações de configuração; cada uma devolve `Finding`s |
| `internal/integrations` | Adaptadores para Trivy, CrowdSec, Suricata, Falco |
| `internal/watch` | Laço de monitoramento contínuo e correlação de eventos |
| `internal/alert` | Deduplicação, limitação de frequência e envio aos notificadores |
| `internal/intel` | Bases públicas: CISA KEV, EPSS (com cache local de 24h) |
| `internal/event` | Tipo `Event` e mapeamento MITRE ATT&CK |
| `internal/store` | Memória local em SQLite: eventos, estado dos achados |
| `internal/ai` | Camada única de provedores de IA |
| `internal/skills` | Carrega e seleciona skills `SKILL.md` |
| `internal/mcp` | Servidor MCP somente leitura |
| `internal/report` | Relatório em Markdown e JSON |

## Modelo de dados

```go
type Severity int // Info, Low, Medium, High, Critical

type Finding struct {
    ID          string   // ex.: "container.privileged"
    Severity    Severity
    Target      string   // container, URL ou tabela
    Title       string
    Detail      string
    Remediation string
    References  []string
    CIS         string   // ex.: "5.4" (CIS Docker Benchmark v1.6)
    CWE         []string // ex.: ["CWE-250"]
    CVE         string   // para achados do Trivy
    KEV         bool     // presente no catálogo CISA KEV
    EPSS        float64  // 0..1
}

type Event struct {          // sinal em tempo real vindo de uma integração
    Source    string         // crowdsec | suricata | falco
    Severity  Severity
    Time      time.Time
    SourceIP  string
    Target    string         // container/aplicação correlacionada
    Summary   string
    Technique string         // MITRE ATT&CK, ex.: "T1110"
    Raw       json.RawMessage // mantido localmente, nunca enviado sem redação
}
```

## Decisões

### Detecção delegada a projetos maduros
Escrever e manter assinaturas para "todo ataque conhecido" é trabalho de comunidades inteiras.
O Sentinels consome a saída dessas ferramentas (todas gratuitas) e agrega valor em três pontos:
**correlação** (qual container/aplicação foi alvo), **contexto** (stack e vulnerabilidades
já conhecidas daquele alvo) e **alerta unificado**.

| Ferramenta | Cobre |
|------------|-------|
| Trivy | CVEs em imagens e dependências |
| CrowdSec | padrões maliciosos em logs web e SSH, reputação de IP |
| Suricata | tráfego de rede (regras abertas) |
| Falco | comportamento suspeito dentro de containers |

Cada integração é opcional; `sentinels doctor` mostra quais estão disponíveis.

### IA opcional e sem poder de ação
- A detecção e os alertas funcionam sem IA.
- A IA recebe apenas texto já redigido (IPs internos, tokens, e-mails e segredos mascarados) e
  devolve apenas texto. Ela não chama ferramentas nem executa comandos.
- Conteúdo de eventos pode ser controlado por quem ataca; ele é enviado como dado delimitado,
  truncado, e a resposta da IA nunca é interpretada como instrução.
- Provedores: Anthropic, OpenAI, Gemini e qualquer API compatível com OpenAI (OpenRouter,
  Ollama, LM Studio, Groq) via `base_url`.

### Bases de conhecimento
Cada `Finding` carrega referências padronizadas para o administrador saber de onde vem a regra:

| Base | Onde entra |
|------|------------|
| CIS Docker Benchmark v1.6 | campo `CIS` nas verificações de container |
| OWASP Top 10 / ASVS | campo `References` nas verificações web |
| CWE | campo `CWE` (vem do Trivy para CVEs; fixo nas verificações próprias) |
| CISA KEV | CVE presente no catálogo → severidade **Crítico** e marcação `KEV` |
| EPSS | score de 0 a 1; ≥ 0,5 eleva para no mínimo **Alto**; ordena o relatório |
| MITRE ATT&CK | campo `Technique` nos `Event`s de tempo real (etapa 3) |

KEV e EPSS são baixados de fontes oficiais (CISA e FIRST) e guardados em cache local por 24h.
Sem internet, o relatório é gerado sem esse enriquecimento e avisa isso no topo.

### Alertas emergenciais
O KEV demora dias para incluir uma falha nova. Caso real: PHP2Shell (CVE-2026-109618 e
CVE-2026-109619, PHP, 21/10/2026) estava com tentativas de exploração relatadas e ainda fora do
KEV em 22/10. Para cobrir essa janela o Sentinels mantém `internal/intel/advisories.json`:

- lista **embutida no binário** (funciona offline);
- **feed** no repositório, baixado a cada 6h, para os agentes instalados receberem alertas novos sem
  nova versão;
- o feed só **acrescenta** alertas: não substitui os embutidos, então um feed adulterado não
  consegue silenciar um alerta;
- o feed é **assinado com Ed25519** (`advisories.json.sig`); a chave pública está no binário e
  conteúdo sem assinatura válida nunca é usado nem vai para o cache (`cmd/feedsign` assina);
- casamento por produto e versão, com versão vinda da variável `PHP_VERSION` das imagens oficiais
  ou do header `X-Powered-By`. Versões de distribuição (`8.3.6-1ubuntu…`) recebem "confirme o
  patch do fornecedor", porque Debian/Ubuntu corrigem sem mudar o número.

Aplicações PHP (WordPress, Moodle, Nextcloud, GLPI, Laravel…) são identificadas pela imagem e
sempre passam por essa verificação; sem versão visível, o relatório pede a checagem manual.

### Skills de segurança
Diretórios com `SKILL.md` (frontmatter `name` + `description`, corpo em Markdown), embutidos no
binário e complementados por `/etc/sentinels/skills/`. Para cada tarefa da IA (resumir relatório,
triar alerta, sugerir correção) o Sentinels escolhe as skills pela `description` e as inclui no
prompt de sistema. Assim o mesmo conhecimento vale para qualquer provedor.

Skills iniciais: `triagem-alertas`, `hardening-docker`, `hardening-vps`, `postgres-rls`,
`resposta-incidentes`, `lgpd-incidentes`.

### Servidor MCP (etapa 7)
`sentinels mcp` implementa o Model Context Protocol (JSON-RPC 2.0; versões 2024-11-05 a
2025-11-25) com 7 ferramentas de consulta — detalhes em [MCP.md](MCP.md).
- **Somente leitura de fato**: o SQLite é aberto com `mode=ro`; nenhuma ferramenta escreve.
- **stdio** (padrão, normalmente via `ssh`) ou **Streamable HTTP** com token obrigatório,
  localhost por padrão, verificação de `Origin`.
- Respostas redigidas como na IA (segredos, `[IP-n]`), campos de log marcados como não
  confiáveis, saída limitada a 60 KB.
- Validado com o MCP Inspector oficial (`--cli`: initialize, tools/list, tools/call).

### Rascunho de alertas emergenciais (etapa 7)
`feedsign draft -in <aviso>` pede à IA a entrada do feed e valida: formato de cada campo, e
cada CVE, versão corrigida e URL **precisa constar no texto da fonte**. Produto sem detecção de
versão no agente é apontado (`intel.SupportedProducts`). Inclusão no feed e assinatura são
manuais.

### Como o agente aprende
"Aprender" não é treinar modelo. São três fontes, cada uma com seu lugar:

| O quê | Onde | Como |
|-------|------|------|
| Ameaças novas no mundo | feeds públicos | alertas emergenciais, KEV, EPSS e regras atualizadas de CrowdSec, Suricata (`suricata-update`) e Falco |
| O normal deste servidor | SQLite local | histórico de eventos e achados (novo × recorrente × resolvido); linha de base de IPs/portas/volume (etapa 4+) |
| O que o admin ensina | SQLite local | falso positivo / confirmado em cada alerta (etapa 4) |

**Memória: SQLite embutido** (`/var/lib/sentinels/sentinels.db`, driver em Go puro, sem servidor).
Guarda eventos com deduplicação, o estado de cada achado entre varreduras e, depois, feedback e
linha de base. Retenção padrão de 90 dias.

**Janela: cofre compatível com Obsidian** (opcional, etapa 5). O agente escreve relatórios,
incidentes e uma nota por aplicação em Markdown com links `[[...]]`; o admin abre a pasta no
Obsidian. O Obsidian não é o cérebro: não roda em servidor sem interface e não responde as
consultas que o agente faz continuamente.

**Cuidados**
- *Envenenamento da linha de base*: aprendizado só em janela inicial definida, e nada que tenha
  casado com assinatura de ataque entra como "normal".
- A IA **sugere**, o humano **aprova**. Nenhuma regra criada por IA entra em produção sozinha.
- Eventos guardados contêm texto controlado por quem ataca; voltam para a IA só como dado.

### Tempo real (etapa 3)

```
CrowdSec LAPI ──(poll /v1/decisions/stream)──┐
Suricata eve.json ──(tail, segue rotação)────┼─► Event ─► ATT&CK ─► Correlação ─► Dedup (SQLite) ─► Alerta
Falco http_output ──(POST 127.0.0.1:2801)────┘                         │
                                                                       └─ achados da última varredura
```

- **Correlação com a varredura**: um evento de exploração (ATT&CK T1190) contra um alvo que tem
  vulnerabilidade conhecida no último relatório (ex.: PHP2Shell) vira **Crítico**, com a falha citada.
- **Mesmo IP em mais de uma fonte** dentro da janela: severidade sobe um nível.
- **Alvo**: Falco informa o container; Suricata é mapeado pela porta de destino publicada; CrowdSec
  informa o IP de origem e o cenário.
- **Deduplicação**: chave fonte + regra + IP + alvo dentro de `alerts.dedup_window`; repetições
  só incrementam o contador.
- A varredura completa roda a cada `scan.interval` dentro do `watch`.

### Notificações (etapa 4)
- Um *worker* e uma fila por canal: canal lento ou fora do ar não atrasa a detecção nem os outros.
- Até 3 novas tentativas (2s, 8s, 30s). Erros nunca mostram o token embutido na URL.
- Limite de frequência por canal (balde de fichas): 10 de rajada + 1/min; **Crítico tem cota
  própria** (30 + 1/min), então uma enxurrada de alertas menores não o bloqueia. Ao voltar, o canal
  recebe "N alertas não enviados".
- Texto do atacante tratado como dado em todos os canais: caracteres de controle e de direção
  (bidi) removidos; Telegram sem `parse_mode`; Slack com `& < >` escapados (sem `<!channel>`);
  Discord com `allowed_mentions` vazio e sem prévia de links; e-mail com assunto codificado,
  sem quebra de linha (sem injeção de cabeçalho) e TLS obrigatório fora de localhost; webhook
  assinado com HMAC-SHA256 sobre `timestamp.corpo`.

### Feedback do administrador (etapa 4)
| Comando | Efeito |
|---------|--------|
| `feedback <id> fp` | cria silenciamento com validade (30 dias). Escopo padrão: o mais restrito (alvo, senão IP, senão regra) |
| `feedback <id> confirmed` | IP de origem marcado como hostil por 90 dias: eventos futuros sobem um nível |
| `accept "<id>\|<alvo>" --reason` | risco aceito com justificativa obrigatória e validade (90 dias); sai da contagem e dos alertas, aparece em "Riscos aceitos" no relatório |

Tudo expira — nada fica silenciado para sempre por esquecimento. Eventos silenciados continuam
gravados (`[silenciado]` no `events`). **Rede de segurança**: exploração contra alvo com
vulnerabilidade conhecida ignora qualquer silenciamento e o alerta explica isso.

O esquema do SQLite é versionado (`PRAGMA user_version`) e migrado automaticamente ao abrir.

### IA, skills e cofre (etapa 5)

```
alerta ──► log / notificadores (imediato)
   └────► Explainer (assíncrono, ≤2 simultâneas, teto/hora) ──► Redactor ──► provedor
                                                    resposta ──► SafeMarkdown ──► 2ª mensagem,
                                                                 memória (ai_note) e cofre
```

- **Prompt** = regras fixas do binário + skills selecionadas por tags (≤ 14 mil caracteres) +
  tarefa + dados entre `<dados>` (fechamentos falsos do delimitador são neutralizados).
- **Redactor**: segredos substituídos; IPs/e-mails viram pseudônimos estáveis por requisição;
  IP privado vira `[IP-INTERNO-n]`, loopback `[IP-LOCAL]`. `ai.keep_ips: true` desliga só a
  parte de IPs.
- **SafeMarkdown** na resposta: remove imagens remotas (pixel de rastreio), HTML e embeds.
- **Provedores**: Anthropic (Messages API), OpenAI e compatíveis (chat completions —
  `max_completion_tokens` na OpenAI, `max_tokens` nos demais), Gemini (`generateContent`, chave
  em header). `http://` só para localhost.
- **Cofre**: `Início.md`, `Relatórios/`, `Ativos/`, `Incidentes/`, `Técnicas/`. Escrita atômica,
  nomes de arquivo saneados e restritos ao diretório do cofre. Texto de log sempre em bloco de
  código com cerca maior que qualquer sequência de crases do conteúdo. Trecho após
  `<!-- sentinels:notas -->` é do administrador e é preservado.

### Volume de alertas das varreduras (etapa 6)
- Primeira varredura (sem histórico na memória) = linha de base: **um** resumo.
- Depois: alerta individual para achado novo de configuração, CVE no KEV ou alerta emergencial
  (máx. 10 por varredura, o resto resumido); demais CVEs novas agrupadas por alvo.
- CVEs de pacotes do kernel dentro das imagens são descartadas (containers usam o kernel do host)
  e contadas no relatório. Em teste com `php:8.3.10-apache`: 1.267 de 1.536 CVEs eram do kernel;
  a primeira varredura passou de 1.537 alertas para 1.

### Implantação (etapa 6)
- **Docker**: distroless `static-debian13:nonroot` + Trivy, usuário 65532, rootfs somente
  leitura, sem capabilities; API do Docker via `docker-socket-proxy` (só GET de containers e
  imagens). `DOCKER_HOST` é respeitado.
- **systemd**: usuário dedicado, sandbox (`systemd-analyze security` 1.7), escreve só em
  `/var/lib/sentinels`.
- **Release**: binários amd64/arm64 + `checksums.txt`; o `install.sh` verifica o SHA-256.

### Somente leitura
O agente lê a API do Docker e arquivos de log. Nenhuma ação de bloqueio na v1 — evita que
um falso positivo derrube produção. Bloqueio fica a cargo do CrowdSec bouncer, se o usuário quiser.

### Verificação de Row-Level Security (PostgreSQL)
Com uma conexão somente leitura informada na configuração, o agente consulta o catálogo:

- tabelas com coluna de tenant (`org_id`, `organization_id`, `tenant_id`, `school_id`…) e
  `relrowsecurity = false` → **Crítico**;
- RLS habilitado sem `relforcerowsecurity` e aplicação conectando como owner → **Alto**
  (o owner ignora as políticas);
- role da aplicação com `SUPERUSER` ou `BYPASSRLS` → **Crítico**;
- tabela com RLS habilitado e nenhuma política → **Médio** (bloqueia tudo; provável erro).

Recomendações do relatório seguem as práticas corretas: `set_config('app.org_id', $1, true)`
dentro de transação (equivalente a `SET LOCAL`), nunca interpolação de string, e
`FORCE ROW LEVEL SECURITY` nas tabelas multitenant.

## Configuração

Arquivo: `/etc/sentinels/sentinels.yaml` (exemplo em `sentinels.example.yaml`).
Segredos (chave de IA, tokens de notificação, DSN do banco) sempre via variáveis de ambiente.

## Execução

- **systemd**: binário em `/usr/local/bin/sentinels`, usuário dedicado `sentinels` no grupo
  `docker` (leitura do socket).
- **Docker**: socket montado como `:ro`, sistema de arquivos somente leitura.

## Fora de escopo (v1)
- Bloqueio automático de IPs ou containers.
- Captura de pacotes própria (fica com o Suricata).
- Painel web.
