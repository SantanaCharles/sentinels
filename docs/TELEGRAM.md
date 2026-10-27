# Conversar com o agente pelo Telegram

Além de receber alertas, você pode consultar o agente e responder aos alertas pelo chat.

## Ativar

`sentinels setup` → **Notificações**:
- canal Telegram novo: responda "Sim" em *"Conversar com o agente por este chat?"*;
- canal que já existe: escolha **💬 ativar conversa**.

Salve e reinicie o agente (Portainer: Update the service / Restart). No chat, mande `/help`.

## O que dá para fazer

| No chat | Resposta |
|---------|----------|
| `/status` | última varredura, críticos abertos, eventos das últimas 24 h (se a primeira varredura ainda estiver rodando, avisa e manda o status quando terminar) |
| `/blocked` · `/bloqueados` · `/blocked 13.140` · `/blocked ssh` | IPs bloqueados agora pelo CrowdSec (detecções deste servidor e bans manuais), cenário, tempo restante e quantos eventos o IP gerou em 30 dias. A lista da comunidade do CrowdSec não entra. Desbloquear continua sendo no SSH: `sudo cscli decisions delete --ip IP` |
| `/metrics` · `/metricas` | tempo médio de correção (MTTR), críticos abertos há mais de 7 dias, taxa de falso positivo, IPs que mais atacaram e técnicas ATT&CK mais vistas |
| `/report` · `/relatorio` · `/report hoje` | resumo do dia anterior (ou de hoje até agora): total e severidade, **países de onde mais vieram ataques**, IPs mais ativos e o **tipo de ataque** (técnica ATT&CK). Mesmo conteúdo do relatório diário automático |
| `/update` · `/atualizar` | verifica no GitHub se há uma versão mais nova e mostra o comando para atualizar. **Não** atualiza sozinho — o bot só consulta |
| `/doctor` | o que o Sentinels tem ativo (Docker, Trivy, CrowdSec, Suricata, Falco, IA, canais) e os comandos exatos para instalar o que falta — você roda no SSH |
| `/inventory` · `/inventory php` | o que está rodando: containers, imagem, stack, portas públicas e problemas de cada um (pacotes instalados direto no sistema não entram) |
| `/scan` | confirma na hora ("Em poucos minutos te mando o status"), roda uma varredura completa e manda o status ao terminar |
| `/findings` · `/findings critical` · `/findings all` | problemas abertos |
| `/events` · `/events 72` | ataques e eventos recentes, numerados |
| `/event 12` | detalhe do evento, análise da IA e botões |
| `/muted` | regras de falso positivo ativas |
| Botões nos alertas | **✅ Ataque real** · **🔕 Falso positivo** · **🤖 Explicar** |
| Qualquer pergunta | respondida pela IA configurada, ex.: *"o que aconteceu hoje?"*, *"o PHP da loja está vulnerável?"* |

Tudo que demora responde na hora com uma confirmação — "🤔 Analisando sua pergunta…",
"🤖 Analisando o evento #12…", "🔎 Iniciando uma varredura…" — e a resposta completa chega em
seguida.

Os nomes em português das versões anteriores (`/varrer`, `/achados`, `/eventos`, `/evento`,
`/silenciados`, `/ajuda`) continuam funcionando.

Os botões fazem o mesmo que `sentinels feedback` no terminal: falso positivo silencia eventos
iguais por 30 dias (exceto exploração contra alvo vulnerável); ataque real faz o IP pesar mais
nos próximos alertas por 90 dias.

## Segurança

- **Só o chat configurado é atendido.** Mensagens e botões vindos de qualquer outro chat são
  ignorados (e registrados uma vez no log). Em grupo, todos os membros do grupo podem usar o bot —
  use um grupo só da equipe.
- **Nada é alterado no servidor.** O bot consulta dados e grava feedback; não reinicia
  containers, não bloqueia IPs, não executa comandos.
- **Sem porta aberta.** O agente busca as mensagens no Telegram (long polling).
- **Mensagens antigas são ignoradas**: o que chegou enquanto o agente estava parado não é
  respondido.
- Respostas em texto simples (sem formatação), segredos mascarados; perguntas à IA usam a mesma
  redação dos alertas (`[IP-1]`…) e contam no limite `ai.max_calls_per_hour`.

## Vários servidores

O Telegram permite **um único leitor por bot**. Com mais de um agente (vários servidores ou um
Swarm com vários nós), crie **um bot por servidor** para a conversa — o mesmo grupo pode receber
os alertas de todos. Se dois agentes lerem o mesmo bot, o log mostra
*"outro processo está lendo este bot"*.

## Por que o bot não instala nada

Instalar CrowdSec, Suricata ou Falco exige root no servidor. Se o bot pudesse fazer isso, quem
tomasse sua conta do Telegram — ou conseguisse injetar texto que a IA obedecesse — ganharia root na
VPS com uma mensagem. Por isso o `/doctor` mostra o que falta e os comandos prontos, e quem executa
é você, pelo SSH. O agente continua somente leitura.
