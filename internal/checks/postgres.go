package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

// Normalized (lower-case, no underscores) column names that mark a table as
// multitenant. Covers snake_case and Prisma camelCase.
var tenantColumns = []string{
	"orgid", "organizationid", "organisationid", "tenantid", "schoolid", "escolaid",
	"empresaid", "companyid", "workspaceid", "clinicaid", "clinicid", "lojaid", "storeid",
}

const rlsDocs = "https://www.postgresql.org/docs/current/ddl-rowsecurity.html"

const rlsHowTo = "Em cada requisição, dentro de uma transação: `SELECT set_config('app.org_id', $1, true)` " +
	"(equivale a SET LOCAL e não vaza para outras requisições do pool). Na política: " +
	"`USING (org_id = current_setting('app.org_id')::uuid)`. Nunca monte o SET por interpolação de string."

type tableInfo struct {
	schema, name, owner string
	rls, force          bool
	policies            int
	tenant              bool
}

// Postgres audits Row-Level Security. dsn should belong to a read-only user;
// appRole is the role the application connects as (defaults to the DSN user).
func Postgres(ctx context.Context, name, dsn, appRole string) ([]finding.Finding, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("DSN inválido para %s: %w", name, err)
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["statement_timeout"] = "15000"
	cfg.RuntimeParams["application_name"] = "sentinels-audit"
	if appRole == "" {
		appRole = cfg.User
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("conectando em %s: %w", name, err)
	}
	defer conn.Close(context.Background())

	var out []finding.Finding
	target := func(t string) string { return name + ": " + t }

	var super, bypass bool
	err = conn.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1`, appRole).Scan(&super, &bypass)
	switch {
	case err == pgx.ErrNoRows:
		out = append(out, finding.Finding{
			ID: "postgres.app_role_missing", Severity: finding.Info, Target: target(appRole),
			Title: fmt.Sprintf("Role da aplicação %q não encontrado", appRole),
		})
	case err != nil:
		return nil, fmt.Errorf("lendo roles de %s: %w", name, err)
	case super:
		out = append(out, finding.Finding{
			ID: "postgres.app_superuser", Severity: finding.Critical, Target: target(appRole), CWE: []string{"CWE-250"},
			Title:       "Aplicação conecta como superusuário",
			Detail:      "Superusuários ignoram todas as políticas de RLS e podem ler, alterar ou apagar qualquer dado, além de executar comandos no servidor do banco.",
			Remediation: "Crie um role dedicado sem SUPERUSER (`CREATE ROLE app_user LOGIN NOSUPERUSER NOBYPASSRLS`) com GRANT apenas nas tabelas necessárias.",
			References:  []string{rlsDocs},
		})
	case bypass:
		out = append(out, finding.Finding{
			ID: "postgres.app_bypassrls", Severity: finding.Critical, Target: target(appRole), CWE: []string{"CWE-284"},
			Title:       "Role da aplicação tem BYPASSRLS",
			Detail:      "Com BYPASSRLS nenhuma política de linha é aplicada às consultas da aplicação.",
			Remediation: fmt.Sprintf("`ALTER ROLE %s NOBYPASSRLS;`", appRole),
			References:  []string{rlsDocs},
		})
	}

	rows, err := conn.Query(ctx, `
		SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner),
		       c.relrowsecurity, c.relforcerowsecurity,
		       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)::int,
		       EXISTS (
		         SELECT 1 FROM pg_attribute a
		         WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		           AND replace(lower(a.attname), '_', '') = ANY($1)
		       )
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p')
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname NOT LIKE 'pg\_%'
		  AND c.relname <> '_prisma_migrations'
		ORDER BY 1, 2`, tenantColumns)
	if err != nil {
		return nil, fmt.Errorf("lendo tabelas de %s: %w", name, err)
	}
	var tables []tableInfo
	for rows.Next() {
		var t tableInfo
		if err := rows.Scan(&t.schema, &t.name, &t.owner, &t.rls, &t.force, &t.policies, &t.tenant); err != nil {
			rows.Close()
			return nil, err
		}
		tables = append(tables, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out = append(out, rlsFindings(name, appRole, tables)...)
	return out, nil
}

// rlsFindings is separated from the queries so it can be tested without a database.
func rlsFindings(name, appRole string, tables []tableInfo) []finding.Finding {
	var out []finding.Finding
	for _, t := range tables {
		fq := t.schema + "." + t.name
		sqlName := pgx.Identifier{t.schema, t.name}.Sanitize()
		tgt := name + ": " + fq
		switch {
		case t.tenant && !t.rls:
			out = append(out, finding.Finding{
				ID: "postgres.rls_missing", Severity: finding.Critical, Target: tgt, CWE: []string{"CWE-639"},
				Title:       "Tabela multitenant sem Row-Level Security",
				Detail:      "A tabela tem coluna de tenant, mas o banco não restringe as linhas. Um único erro de filtro na aplicação (ou um parâmetro adulterado) expõe dados de outras organizações.",
				Remediation: fmt.Sprintf("`ALTER TABLE %s ENABLE ROW LEVEL SECURITY; ALTER TABLE %s FORCE ROW LEVEL SECURITY;` e crie as políticas. %s", sqlName, sqlName, rlsHowTo),
				References:  []string{rlsDocs},
			})
		case t.rls && t.policies == 0:
			out = append(out, finding.Finding{
				ID: "postgres.rls_no_policy", Severity: finding.Medium, Target: tgt,
				Title:       "RLS habilitado sem nenhuma política",
				Detail:      "Sem políticas, o acesso fica negado para todos exceto o owner — normalmente sinal de configuração incompleta, e o owner continua vendo tudo.",
				Remediation: "Crie políticas para SELECT, INSERT, UPDATE e DELETE.",
				References:  []string{rlsDocs},
			})
		case t.rls && !t.force && t.owner == appRole:
			out = append(out, finding.Finding{
				ID: "postgres.rls_not_forced", Severity: finding.High, Target: tgt, CWE: []string{"CWE-284"},
				Title:       "RLS não é forçado e a aplicação é dona da tabela",
				Detail:      fmt.Sprintf("O owner (%s) ignora as políticas a menos que a tabela use FORCE ROW LEVEL SECURITY. Na prática o RLS não está protegendo nada.", t.owner),
				Remediation: fmt.Sprintf("`ALTER TABLE %s FORCE ROW LEVEL SECURITY;` — ou faça a aplicação conectar com um role que não seja o owner.", sqlName),
				References:  []string{rlsDocs},
			})
		}
	}
	return out
}
