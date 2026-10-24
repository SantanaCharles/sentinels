# Sentinels

Agente de segurança **gratuito e open source** para servidores e VPS. Instale no seu servidor e ele:

1. **Descobre** os containers e aplicações publicadas e identifica a stack de cada uma.
2. **Audita** a configuração e gera um relatório de vulnerabilidades críticas.
3. **Monitora** em tempo real os sinais de ataque coletados por ferramentas consagradas.
4. **Alerta** os administradores (Telegram, Slack, Discord, e-mail ou webhook).
5. **Explica** os achados com a IA de sua escolha — Claude, GPT, Gemini, OpenRouter, Ollama, LM Studio.

> Status: **v0.1 — pronto para testes em servidor**. Veja o [roadmap](#roadmap).

---

## Por que o Sentinels

Pequenas equipes publicam aplicações em uma VPS com Docker e raramente têm tempo para auditar
configuração, acompanhar CVEs e olhar logs. O Sentinels junta essas tarefas em um único agente
leve, sem custo e sem enviar dados para lugar nenhum além do que você configurar.

## Princípios

- **Não reinventar detecção.** Assinaturas de ataque conhecidas são mantidas por projetos
  maduros (Trivy, CrowdSec, Suricata, Falco). O Sentinels integra, correlaciona e alerta.
- **IA fora do caminho crítico.** A detecção funciona sem IA. A IA só resume relatórios e
  explica alertas, nunca executa ações no servidor.
- **Privacidade por padrão.** Valores de segredos nunca são lidos nem enviados; só os nomes.
  Dados enviados à IA passam por redação (mascaramento) antes.
- **Somente leitura.** O agente observa e alerta. Não bloqueia, não altera containers.
- **Um binário, sem dependências.** Escrito em Go.

## O que é verificado

| Área | Exemplos de verificação |
|------|-------------------------|
| Containers | container privilegiado, `docker.sock` montado, rodando como root, rede do host |
| Exposição | banco de dados ou painel administrativo acessível pela internet |
| Imagens | CVEs conhecidas via Trivy |
| Web | headers de segurança ausentes, versão do servidor exposta |
| Banco (PostgreSQL) | tabelas multitenant sem Row-Level Security, RLS sem `FORCE`, app conectando como owner/superuser |
| Tempo real | alertas de CrowdSec, Suricata e Falco correlacionados por container/aplicação |

## Bases de conhecimento

| Base | Uso |
|------|-----|
| CIS Docker Benchmark | referência das verificações de containers |
| OWASP Top 10 / ASVS | verificações web |
| Alertas emergenciais | falhas graves exploradas **antes** de entrarem no KEV (ex.: PHP2Shell, out/2026) |
| CISA KEV | CVEs exploradas ativamente sobem para **Crítico** |
| EPSS | probabilidade de exploração, ordena o que corrigir primeiro |
| MITRE ATT&CK | nome padrão da técnica em cada alerta |
| CWE | tipo de falha e referência de correção |

## Skills de segurança para a IA

Arquivos `SKILL.md` (formato aberto de Agent Skills) com conhecimento por tema — triagem de
alertas, hardening Docker/VPS, RLS no PostgreSQL, resposta a incidentes, LGPD. O Sentinels envia
a skill relevante junto do contexto, então funciona com qualquer provedor. Skills próprias podem
ser adicionadas em `/etc/sentinels/skills/` — veja [docs/SKILLS.md](docs/SKILLS.md).

Embutidas: `triagem-alertas`, `resposta-incidentes`, `lgpd-incidentes`, `postgres-rls`,
`hardening-docker`, `hardening-vps`, `php-seguranca`, `seguranca-web`.

## Instalação

**Docker Compose** (recomendado — já inclui o Trivy e usa um proxy somente leitura no lugar do
socket do Docker):

```bash
git clone https://github.com/SantanaCharles/sentinels && cd sentinels/deploy
cp sentinels.docker.yaml sentinels.yaml
cp sentinels.env.example sentinels.env && chmod 600 sentinels.env
docker compose up -d
```

**Binário + systemd** (confere o SHA-256 de tudo antes de instalar):

```bash
curl -fsSL https://github.com/SantanaCharles/sentinels/releases/latest/download/install.sh -o install.sh
sudo sh install.sh
sudo systemctl enable --now sentinels
```

Detalhes, hardening e atualização: [docs/INSTALACAO.md](docs/INSTALACAO.md).

## Primeiros passos: `sentinels setup`

```bash
sudo sentinels setup            # menu com setas: ↑ ↓ para navegar, Enter para escolher
sudo sentinels setup ia         # direto numa seção: rapida, ia, notificacoes, integracoes, bancos, varredura, cofre, mcp
```

```
┃ O que você quer configurar?
┃ > ⚡ Configuração rápida        IA + um canal de alerta + teste, em 2 minutos
┃   🤖 Inteligência artificial    provedor, modelo, chave e uso
┃   🔔 Notificações               Telegram, Slack, Discord, e-mail, webhook
┃   🛰  Integrações                Trivy, CrowdSec, Suricata, Falco
┃   🐘 Bancos PostgreSQL          auditoria de Row-Level Security
┃   🔍 Varredura e alertas        intervalo, severidade, URLs públicas
┃   📓 Cofre Obsidian             notas de relatórios e incidentes
┃   🔌 Servidor MCP               consultar o agente pelo Claude/ChatGPT
┃   🩺 Verificar instalação (doctor)
┃   💾 Salvar e sair
```

- **Modelos reais**: a lista vem da API do provedor (Claude, OpenAI, Gemini, OpenRouter, Ollama,
  LM Studio) — digite `/` para filtrar.
- **Telegram sem caçar o chat_id**: crie o bot no @BotFather, mande uma mensagem para ele e o
  assistente encontra a conversa.
- **Testa na hora**: IA, cada canal de alerta e a conexão com o banco.
- **Segredos separados**: chaves e tokens vão para `sentinels.env` (0600), nunca para o YAML;
  campos de senha não aparecem na tela. A versão anterior da configuração fica em `.bak`.
- Sem terminal interativo (ou com `--plain`) vira perguntas simples, uma por linha.

Para scripts: `sentinels config show`, `config get ai.model`, `config set alerts.min_severity critical`,
`config set-secret SENTINELS_AI_KEY` (lê sem eco).

## Uso

```bash
sentinels scan            # varredura completa + relatório (Markdown e JSON)
sentinels scan --offline  # sem baixar KEV/EPSS/feed de alertas
sentinels scan --fail-on high   # código de saída 3 se houver achado Alto ou Crítico (CI)
sentinels watch           # tempo real + varredura periódica, correlação e alertas
sentinels watch --json    # alertas em JSON (um por linha)
sentinels events --since 24h --min low   # histórico guardado na memória local
sentinels notify-test     # envia um alerta de teste para todos os canais
sentinels ai-test         # testa a IA configurada e lista as skills carregadas
sentinels explain 42      # análise da IA de um evento
sentinels mcp             # servidor MCP: pergunte ao Claude/ChatGPT sobre o servidor (docs/MCP.md)
sentinels doctor          # verifica integrações instaladas
```

### Ensinando o agente

```bash
sentinels feedback 42 fp --note "monitoramento interno"   # falso positivo: silencia eventos iguais por 30 dias
sentinels feedback 42 fp --scope rule                      # silencia a regra em qualquer alvo/IP
sentinels feedback 57 confirmed                            # ataque real: o IP passa a pesar mais por 90 dias
sentinels suppressions                                     # lista silenciamentos (remove: suppressions remove <id>)
sentinels findings                                         # achados abertos, com a chave de cada um
sentinels accept "container.root_user|db" --reason "imagem oficial troca de usuário no entrypoint"
```

Um silenciamento **nunca** cala uma tentativa de exploração contra um alvo com vulnerabilidade
conhecida — essa rede de segurança não pode ser desligada por feedback.

```bash
sentinels version
```

## Conectando uma IA

```yaml
ai:
  enabled: true
  provider: anthropic        # anthropic | openai | gemini | openrouter | ollama | lmstudio | openai-compatible
  model: claude-sonnet-5-5
  api_key_env: SENTINELS_AI_KEY
```

| Provedor | `provider` | Chave |
|----------|-----------|-------|
| Claude | `anthropic` | sim |
| GPT | `openai` | sim |
| Gemini | `gemini` | sim |
| OpenRouter (qualquer modelo) | `openrouter` | sim |
| Ollama / LM Studio (local, nada sai do servidor) | `ollama` / `lmstudio` | não |
| Groq, Together, vLLM… | `openai-compatible` + `base_url` | conforme o serviço |

O que a IA faz:
- **Resumo executivo** no topo de cada relatório, com as 5 prioridades.
- **Análise dos alertas graves** (padrão: Crítico), enviada como segunda mensagem — o alerta
  original nunca espera pela IA. Teto de chamadas por hora para controlar custo.
- `sentinels explain <evento>` — análise sob demanda de qualquer evento guardado.

Antes de sair do servidor, o texto passa por redação: senhas, tokens, chaves (AWS, Stripe,
GitHub, Google, Telegram), JWT e CPF são removidos; IPs e e-mails viram pseudônimos (`[IP-1]`).
A chave é lida de variável de ambiente, nunca do arquivo de configuração.

## Cofre Obsidian

Com `vault.enabled: true`, o agente mantém uma pasta de notas Markdown: relatórios, um
incidente por alerta (com a análise da IA), uma nota por ativo e por técnica ATT&CK, todas
ligadas por `[[links]]` — o grafo do Obsidian mostra qual ataque atingiu qual aplicação.
O que você escrever abaixo de "Notas do administrador" é preservado. Texto vindo dos logs fica
sempre em bloco de código, para que nada injetado por um atacante seja renderizado.

## Documentação

- [Instalação](docs/INSTALACAO.md)
- [Arquitetura](docs/ARQUITETURA.md)
- [Política de segurança](SECURITY.md)
- [Integrações de tempo real (CrowdSec, Suricata, Falco)](docs/INTEGRACOES.md)
- [Escrevendo skills](docs/SKILLS.md)
- [Servidor MCP (Claude Code, Claude Desktop, ChatGPT…)](docs/MCP.md)

## Roadmap

- [x] 1 — Base do projeto e documentação
- [x] 2 — Varredura (containers, stack, exposição, RLS, CVEs via Trivy) com CIS, CWE, CISA KEV, EPSS e alertas emergenciais
- [x] 3 — Tempo real: CrowdSec, Suricata e Falco, alertas classificados com MITRE ATT&CK, memória local em SQLite
- [x] 4 — Alertas (Telegram, Slack, Discord, e-mail, webhook) + feedback do admin (falso positivo / confirmado)
- [x] 5 — Provedores de IA + skills de segurança (`SKILL.md`) + cofre compatível com Obsidian
- [x] 6 — Instalador, serviço systemd, imagem Docker e assinatura do feed de alertas
- [x] 7 — Servidor MCP (consulta pela IA, somente leitura) + rascunho de alertas emergenciais pela IA

Próximos: teste em VPS real, botões de feedback no Telegram, linha de base de tráfego normal,
detecção de versão de mais runtimes (Node.js, Java, Python) para os alertas emergenciais.

## Licença

[Apache-2.0](LICENSE) — uso livre, inclusive comercial.

Feito por [Smart Code Tecnologia](https://smartcodetecnologia.com.br).
