---
name: postgres-rls
description: Row-Level Security no PostgreSQL para aplicações multitenant — como funciona, armadilhas comuns e a forma correta de implementar com pools de conexão e ORMs como Prisma.
metadata:
  applies-to: "postgres.*, stack:postgresql"
---

# Row-Level Security (PostgreSQL)

RLS faz o banco recusar linhas de outro tenant mesmo que a aplicação esqueça o filtro
`WHERE org_id = ...`. É a última barreira contra vazamento entre clientes (OWASP A01, CWE-639).

## Implementação correta
```sql
ALTER TABLE "Aluno" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Aluno" FORCE ROW LEVEL SECURITY;   -- vale também para o owner
CREATE POLICY tenant_isolation ON "Aluno"
  USING      ("orgId" = current_setting('app.org_id')::uuid)
  WITH CHECK ("orgId" = current_setting('app.org_id')::uuid);
```
Na aplicação, em toda requisição, **dentro de uma transação**:
```sql
SELECT set_config('app.org_id', $1, true);   -- true = vale só nesta transação (SET LOCAL)
```
Com Prisma, envolva cada operação numa transação interativa que primeiro chama
`set_config` via `$executeRaw` com o orgId como **parâmetro** (template tag do Prisma, nunca
`$executeRawUnsafe` com concatenação) — normalmente numa extensão do client (`$extends`).

## Armadilhas
- **Owner ignora RLS** sem `FORCE ROW LEVEL SECURITY`. Migrações costumam rodar com o mesmo
  usuário da aplicação, que vira owner das tabelas.
- **Superusuário e BYPASSRLS** ignoram tudo. A imagem oficial do Postgres cria `POSTGRES_USER`
  como superusuário — crie um role separado para a aplicação.
- **`SET` sem `LOCAL` vaza entre requisições** em pools (PgBouncer, Prisma): a próxima
  requisição na mesma conexão herda o tenant anterior.
- **Interpolar o valor no SQL** (`SET app.org_id = '${id}'`) é injeção de SQL. Use parâmetro.
- `current_setting('app.org_id')` sem valor gera erro — falha fechada, que é o desejado. Nunca
  escreva políticas do tipo `... OR current_setting(...) IS NULL`: isso transforma "tenant não
  definido" em "acesso a tudo".
- RLS habilitado **sem política** nega tudo para quem não é owner — normalmente erro de migração.
- Não existe trigger `AFTER SELECT` no PostgreSQL; para auditoria de leitura use pgaudit.

## Verificação
```sql
SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
WHERE relnamespace = 'public'::regnamespace AND relkind = 'r';
SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user;
```
