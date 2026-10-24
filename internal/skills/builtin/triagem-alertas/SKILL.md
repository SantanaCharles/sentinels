---
name: triagem-alertas
description: Como avaliar se um alerta de segurança é ataque real, falso positivo ou inconclusivo, e como responder no formato padrão do Sentinels.
metadata:
  applies-to: "task:triage, task:explain"
---

# Triagem de alertas

## Formato da resposta (siga exatamente)

**Avaliação:** provável ataque real | provável falso positivo | inconclusivo — uma frase com o motivo.
**O que aconteceu:** 1 a 2 frases em linguagem simples.
**Risco para este servidor:** considere o alvo e as vulnerabilidades conhecidas citadas nos dados.
**Faça agora:** no máximo 3 passos, do mais urgente ao menos urgente.
**Para confirmar:** 1 a 3 comandos somente leitura.

Máximo de 220 palavras.

## Sinais de ataque real
- Alvo com vulnerabilidade conhecida que combina com a técnica (ex.: exploração T1190 contra
  aplicação com CVE crítica) — trate como provável comprometimento até provar o contrário.
- O mesmo IP aparece em mais de um motor (CrowdSec + Suricata + Falco) ou já foi confirmado
  pelo administrador.
- Sequência coerente: reconhecimento → exploração → execução no container (shell, download de
  ferramentas, conexões de saída novas).
- Evento do Falco (dentro do container) depois de evento de rede contra o mesmo alvo.

## Sinais de falso positivo
- Origem interna conhecida ([IP-INTERNO-n]) fazendo algo rotineiro: monitoramento, backup,
  health check, CI/CD.
- Varredura (T1595/T1046) isolada, sem exploração em seguida: é o ruído de fundo da internet.
- Shell em container logo após deploy ou manutenção, sem tráfego suspeito antes.

## Regras de severidade
- Reconhecimento sozinho raramente é urgente. Exploração contra alvo vulnerável é sempre urgente.
- Na dúvida entre falso positivo e ataque real em alvo vulnerável, escolha "inconclusivo" e
  oriente a verificação — nunca recomende ignorar.
- Se o alerta foi bloqueado (CrowdSec/Suricata), diga isso e foque em verificar se houve
  tentativa bem-sucedida antes do bloqueio.
