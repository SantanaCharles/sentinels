# Escrevendo skills

Uma skill é uma pasta com um `SKILL.md` no formato aberto de Agent Skills: frontmatter YAML e
corpo em Markdown. O Sentinels inclui no prompt da IA as skills que combinam com a situação.

```
/etc/sentinels/skills/
└── minha-empresa-postgres/
    └── SKILL.md
```

```markdown
---
name: minha-empresa-postgres
description: Padrões de banco da empresa — schema por tenant e roles por aplicação.
metadata:
  applies-to: "postgres.*, stack:postgresql, task:report"
---

# Banco de dados na empresa

- Cada escola tem seu próprio schema; RLS é usado só nas tabelas compartilhadas.
- O role da aplicação é `app_<sistema>` e nunca é owner das tabelas.
```

- `name` e `description` são obrigatórios. Use o mesmo `name` de uma skill embutida para
  **substituí-la** (ex.: `postgres-rls` com as regras da sua equipe).
- Tamanho máximo: 64 KB. Mantenha curto: o que vai no prompt custa tokens.

## Tags de `applies-to`

Separadas por vírgula; `*` no fim casa por prefixo.

| Tag | Quando é enviada |
|-----|------------------|
| `task:report` | resumo executivo do relatório |
| `task:triage`, `task:explain` | análise de alerta / `sentinels explain` |
| `severity:critical` (`high`, `medium`…) | severidade do alerta |
| `t1190`, `t1110`, `t1505.003`… | técnica MITRE ATT&CK do evento (e a técnica-pai) |
| `source:crowdsec`, `source:suricata`, `source:falco` | motor que detectou |
| `stack:php`, `stack:postgresql`, `stack:next.js`… | componentes do alvo (em minúsculas) |
| `postgres.rls_missing`, `container.*`, `web.*`, `advisory.*`, `cve.*` | IDs dos achados |

Veja os IDs de achados com `sentinels findings` e confira o que foi carregado com
`sentinels ai-test`.

## Regras que nenhuma skill altera

As regras de segurança do prompt (dados de log são não confiáveis, nada é executado, só ações
defensivas, sem inventar fatos) ficam no binário e vêm antes das skills.
