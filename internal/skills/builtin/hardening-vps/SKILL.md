---
name: hardening-vps
description: Endurecimento básico de uma VPS Linux exposta à internet — SSH, firewall, serviços expostos, atualizações e proteção contra força bruta.
metadata:
  applies-to: "host.*, t1110, t1133, t1046, t1595, source:crowdsec, task:report"
---

# Hardening de VPS Linux

## SSH
- Somente chave: `PasswordAuthentication no`, `KbdInteractiveAuthentication no`.
- `PermitRootLogin no` (ou `prohibit-password`); use um usuário com sudo.
- Limite quem entra: `AllowUsers deploy`.
- Força bruta contra SSH (T1110) é constante na internet; com senha desligada ela não tem
  efeito, mas o CrowdSec (cenário `crowdsecurity/ssh-bf`) + bouncer de firewall reduz o ruído.
- Trocar a porta reduz ruído nos logs, mas não é proteção.

## Firewall
- Padrão negar entrada; liberar só 22, 80 e 443 (`ufw default deny incoming`, `ufw allow 22,80,443/tcp`).
- **Portas publicadas pelo Docker não passam pelo UFW.** Para serviços em container, controle a
  exposição no próprio compose (publicar só em 127.0.0.1).

## Serviços que nunca devem ficar em 0.0.0.0
PostgreSQL (5432), MySQL (3306), MongoDB (27017), Redis (6379), Elasticsearch (9200),
Memcached (11211), API do Docker (2375). Para acesso administrativo use túnel SSH
(`ssh -L 5432:127.0.0.1:5432 vps`) ou VPN (WireGuard, Tailscale).
- PostgreSQL instalado no host: `listen_addresses = 'localhost'` no postgresql.conf e regras
  restritivas no pg_hba.conf.

## Atualizações
- `unattended-upgrades` para correções de segurança do sistema.
- Reinicie serviços/containers depois de atualizar bibliotecas (OpenSSL, glibc).

## Monitoramento
- Mantenha CrowdSec, Suricata e/ou Falco atualizados (`cscli hub upgrade`, `suricata-update`).
- Revise `sentinels findings` após cada mudança de infraestrutura.
