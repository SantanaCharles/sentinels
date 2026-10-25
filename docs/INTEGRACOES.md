# Integrações de tempo real

O `sentinels watch` não tem assinaturas próprias de ataque: ele lê os motores abaixo, todos
gratuitos e mantidos por comunidades grandes. Instale os que fizerem sentido; cada um é opcional
e `sentinels doctor` mostra o que foi encontrado.

| Motor | Vê | Melhor para |
|-------|----|-------------|
| [CrowdSec](https://crowdsec.net) | logs (Nginx, Traefik, Caddy, SSH…) | ataques web e força bruta, reputação de IP |
| [Suricata](https://suricata.io) | tráfego de rede | varreduras, exploração em protocolos, C2 |
| [Falco](https://falco.org) | chamadas de sistema dos containers | o que acontece **depois** de uma invasão: shell, escrita em diretórios sensíveis, mineração |

Se for instalar só um: **CrowdSec**. Para containers em produção, some o **Falco**.

## Jeito mais fácil: `sentinels setup install`

```bash
sudo sentinels setup install          # na instalação Docker: cd ~/sentinels/deploy antes
```

O assistente instala e configura cada motor mostrando os comandos e pedindo confirmação:
CrowdSec (chave do Sentinels, logs do proxy em container, porta 8080, bloqueio no firewall com
`DOCKER-USER` e o seu IP liberado), Suricata (interface, regras, volume no compose) e Falco
(driver moderno e envio dos alertas). Na instalação via Docker/Portainer, instale antes só o
comando no host: `sudo sh install.sh --cli-only`.

As seções abaixo descrevem a instalação **manual**, para outras distribuições ou para quem
prefere fazer à mão. Para testar a detecção depois, veja [OPERACAO.md](OPERACAO.md#3-testar-a-detecção-ataques-simulados).

## CrowdSec

```bash
curl -s https://install.crowdsec.net | sudo sh
sudo apt install crowdsec
sudo cscli collections install crowdsecurity/nginx crowdsecurity/linux   # ajuste à sua stack
sudo cscli bouncers add sentinels          # copie a chave exibida
```

`/etc/sentinels/sentinels.env`:
```
SENTINELS_CROWDSEC_KEY=<chave>
```

O Sentinels lê apenas as decisões geradas **neste servidor** (origem `crowdsec`/`cscli`); a lista
comunitária (CAPI) é ignorada para não gerar milhares de alertas. Para o CrowdSec também
bloquear, instale um bouncer (ex.: `crowdsec-firewall-bouncer-iptables`) — o Sentinels não bloqueia.

## Suricata

```bash
sudo apt install suricata
sudo suricata-update                         # baixa as regras ET Open
sudo systemctl enable --now suricata
```

Confira em `/etc/suricata/suricata.yaml` que `eve-log` está habilitado com `- alert`. O Sentinels
segue `/var/log/suricata/eve.json` (inclusive após logrotate) e usa o `mitre_technique_id` das
regras quando existe. Atualize as regras diariamente (`suricata-update` via cron ou timer).

## Falco

```bash
# veja https://falco.org/docs/setup/packages/
sudo apt install falco
```

Em `/etc/falco/falco.yaml`:
```yaml
json_output: true
http_output:
  enabled: true
  url: "http://127.0.0.1:2801/falco"
```

O receptor do Sentinels só aceita `127.0.0.1`/`::1`: qualquer processo que alcance essa porta
consegue injetar eventos, então ela nunca deve ficar exposta.

## Como os eventos são tratados

1. **Classificação** com MITRE ATT&CK (ID explícito da regra quando existe, senão pelo nome).
2. **Alvo**: container do Falco; para o Suricata, container dono da porta de destino.
3. **Correlação**:
   - exploração (T1190, T1059, T1505.003, T1068, T1611, T1133) contra alvo com vulnerabilidade
     conhecida na última varredura → **Crítico**, citando a falha;
   - mesmo IP visto por outro motor na última hora → severidade sobe um nível.
4. **Deduplicação** na janela `alerts.dedup_window`: repetições só aumentam o contador.
5. **Alerta** a partir de `alerts.min_severity`. Tudo fica na memória local
   (`sentinels events --since 24h --min low`).
