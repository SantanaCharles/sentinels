# Writing skills

A skill is a folder with a `SKILL.md` in the open Agent Skills format: YAML frontmatter and a
Markdown body. Sentinels includes in the AI prompt the skills that match the situation.

```
/etc/sentinels/skills/
└── my-company-postgres/
    └── SKILL.md
```

```markdown
---
name: my-company-postgres
description: Company database patterns — schema per tenant and roles per application.
metadata:
  applies-to: "postgres.*, stack:postgresql, task:report"
---

# Database at the company

- Each school has its own schema; RLS is used only on the shared tables.
- The application role is `app_<system>` and is never the owner of the tables.
```

- `name` and `description` are required. Use the same `name` as a built-in skill to **replace it**
  (e.g. `postgres-rls` with your team's rules).
- Maximum size: 64 KB. Keep it short: what goes in the prompt costs tokens.

## `applies-to` tags

Comma-separated; a trailing `*` matches by prefix.

| Tag | When it is sent |
|-----|-----------------|
| `task:report` | the report's executive summary |
| `task:triage`, `task:explain` | alert analysis / `sentinels explain` |
| `severity:critical` (`high`, `medium`…) | the alert's severity |
| `t1190`, `t1110`, `t1505.003`… | the event's MITRE ATT&CK technique (and its parent technique) |
| `source:crowdsec`, `source:suricata`, `source:falco` | the engine that detected it |
| `stack:php`, `stack:postgresql`, `stack:next.js`… | the target's components (lowercase) |
| `postgres.rls_missing`, `container.*`, `web.*`, `advisory.*`, `cve.*` | finding IDs |

See the finding IDs with `sentinels findings` and check what was loaded with `sentinels ai-test`.

## Rules that no skill changes

The prompt's security rules (log data is untrusted, nothing is executed, defensive actions only, no
making up facts) live in the binary and come before the skills.
