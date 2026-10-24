---
name: lgpd-incidentes
description: Obrigações da LGPD e do regulamento da ANPD quando um incidente de segurança pode envolver dados pessoais.
metadata:
  applies-to: "severity:critical, postgres.rls_missing, postgres.app_superuser, postgres.app_bypassrls, web.env_exposed, web.git_exposed, exposure.database_public, t1041, t1003, t1552, task:report"
---

# LGPD e incidentes de segurança

Base: Lei 13.709/2018 (art. 46 a 48) e Resolução CD/ANPD nº 15/2024 (Regulamento de
Comunicação de Incidente de Segurança). Isto é orientação geral; a decisão final deve envolver
o encarregado (DPO) e o jurídico.

## Quando comunicar
Comunique à ANPD **e** aos titulares quando o incidente puder causar **risco ou dano relevante**
aos titulares — por exemplo, envolvendo dados sensíveis, de crianças e adolescentes, dados
financeiros, de autenticação, protegidos por sigilo, ou em larga escala.

## Prazo
**3 dias úteis** a partir do conhecimento de que o incidente afetou dados pessoais. Informações
que ainda não se tem podem ser complementadas depois, de forma justificada.

## O que registrar (sempre, mesmo sem comunicar)
- Data e hora em que o incidente foi conhecido e quando ocorreu.
- Dados e titulares possivelmente afetados (categorias e quantidade estimada).
- Medidas tomadas para conter e reverter os efeitos.
- A justificativa caso decida não comunicar.
O registro de incidentes deve ser guardado por pelo menos 5 anos.

## Como aplicar aos achados do Sentinels
- Tabela multitenant sem RLS, aplicação como superusuário, banco exposto, `.env` público:
  ainda não são incidentes, mas são **falhas de segurança** que a LGPD exige corrigir
  (art. 46 — medidas técnicas aptas a proteger os dados). Trate como prioridade.
- Exploração confirmada em sistema com dados pessoais (ex.: sistema escolar com dados de
  alunos menores): provável incidente comunicável. Oriente acionar o encarregado imediatamente.
- Varredura ou tentativa bloqueada sem acesso a dados: em geral não é comunicável, mas registre.
