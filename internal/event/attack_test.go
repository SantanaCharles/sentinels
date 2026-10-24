package event

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		rule  string
		hints []string
		want  string
	}{
		{"crowdsecurity/ssh-bf", nil, "T1110"},
		{"crowdsecurity/ssh-slow-bf", nil, "T1110"},
		{"crowdsecurity/http-generic-bf", nil, "T1110"},
		{"crowdsecurity/http-probing", nil, "T1595"},
		{"crowdsecurity/http-sensitive-files", nil, "T1595"},
		{"crowdsecurity/http-bad-user-agent", nil, "T1595"},
		{"crowdsecurity/http-cve-2021-41773", nil, "T1190"},
		{"crowdsecurity/http-path-traversal-probing", nil, "T1190"},
		{"crowdsecurity/http-backdoors-attempts", nil, "T1505.003"},
		{"crowdsecurity/ssh-bruteforce-force", nil, "T1110"}, // "force" must not match "rce"
		{"2010937 ET SCAN Suspicious inbound to PostgreSQL port 5432", []string{"Potentially Bad Traffic"}, "T1595"},
		{"2000001 ET WEB_SPECIFIC_APPS Something", []string{"Web Application Attack"}, "T1190"},
		{"Terminal shell in container", []string{"container", "shell", "mitre_execution", "T1059"}, "T1059"},
		{"Detect crypto miners using the Stratum protocol", []string{"mitre_impact"}, "T1496"},
		{"Regra sem pista conhecida", nil, ""},
	}
	for _, c := range cases {
		e := Event{Rule: c.rule}
		Classify(&e, c.hints...)
		if e.Technique != c.want {
			t.Errorf("Classify(%q) = %q, quer %q", c.rule, e.Technique, c.want)
		}
		if c.want != "" && e.Tactic == "" {
			t.Errorf("Classify(%q): tática vazia", c.rule)
		}
	}
}
