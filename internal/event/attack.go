package event

import (
	"regexp"
	"strings"
)

// Technique is an entry of the MITRE ATT&CK Enterprise matrix.
type Technique struct {
	Name   string
	Tactic string
}

// Techniques covers what server-side engines report. Reference:
// https://attack.mitre.org/techniques/enterprise/
var Techniques = map[string]Technique{
	"T1595":     {"Active Scanning", "Reconnaissance"},
	"T1595.002": {"Vulnerability Scanning", "Reconnaissance"},
	"T1046":     {"Network Service Discovery", "Discovery"},
	"T1083":     {"File and Directory Discovery", "Discovery"},
	"T1190":     {"Exploit Public-Facing Application", "Initial Access"},
	"T1133":     {"External Remote Services", "Initial Access"},
	"T1078":     {"Valid Accounts", "Initial Access"},
	"T1110":     {"Brute Force", "Credential Access"},
	"T1003":     {"OS Credential Dumping", "Credential Access"},
	"T1552":     {"Unsecured Credentials", "Credential Access"},
	"T1059":     {"Command and Scripting Interpreter", "Execution"},
	"T1021":     {"Remote Services", "Lateral Movement"},
	"T1213":     {"Data from Information Repositories", "Collection"},
	"T1053":     {"Scheduled Task/Job", "Persistence"},
	"T1098":     {"Account Manipulation", "Persistence"},
	"T1505.003": {"Web Shell", "Persistence"},
	"T1068":     {"Exploitation for Privilege Escalation", "Privilege Escalation"},
	"T1548":     {"Abuse Elevation Control Mechanism", "Privilege Escalation"},
	"T1611":     {"Escape to Host", "Privilege Escalation"},
	"T1562":     {"Impair Defenses", "Defense Evasion"},
	"T1070":     {"Indicator Removal", "Defense Evasion"},
	"T1071":     {"Application Layer Protocol", "Command and Control"},
	"T1105":     {"Ingress Tool Transfer", "Command and Control"},
	"T1041":     {"Exfiltration Over C2 Channel", "Exfiltration"},
	"T1496":     {"Resource Hijacking", "Impact"},
	"T1498":     {"Network Denial of Service", "Impact"},
	"T1499":     {"Endpoint Denial of Service", "Impact"},
	"T1485":     {"Data Destruction", "Impact"},
}

var techniqueRe = regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`)

// FindTechnique extracts an explicit ATT&CK ID (Falco tags, Suricata rule
// metadata). Returns "" when none is present.
func FindTechnique(values ...string) string {
	for _, v := range values {
		if m := techniqueRe.FindString(strings.ToUpper(v)); m != "" {
			return m
		}
	}
	return ""
}

// keywordRules classify rule names that carry no explicit ATT&CK ID. Text is
// normalized to lower-case words separated by single spaces, and each entry is
// matched as whole words ("rce" never matches inside "brute-force").
// First match wins, so more specific patterns come first.
var keywordRules = []struct {
	phrases   []string
	technique string
}{
	{[]string{"webshell", "web shell", "backdoor", "backdoors"}, "T1505.003"},
	{[]string{"cve", "exploit", "exploitation", "appsec", "vpatch", "virtual patching", "sqli", "sql injection", "xss", "traversal", "lfi", "rfi", "rce",
		"injection", "web application attack", "web specific apps"}, "T1190"},
	{[]string{"bf", "bruteforce", "brute force", "password spray"}, "T1110"},
	{[]string{"privilege gain", "privilege escalation"}, "T1068"},
	{[]string{"portscan", "port scan", "network scan"}, "T1046"},
	{[]string{"sensitive files", "probing", "crawl", "bad user agent", "scan", "scanner", "recon"}, "T1595"},
	{[]string{"dos", "ddos", "denial of service", "flood"}, "T1499"},
	{[]string{"miner", "miners", "mining", "cryptominer", "coinminer"}, "T1496"},
	{[]string{"escape", "breakout"}, "T1611"},
	{[]string{"shell", "reverse shell"}, "T1059"},
	{[]string{"credential", "credentials", "shadow"}, "T1003"},
	{[]string{"c2", "cnc", "command and control", "trojan", "malware"}, "T1071"},
}

var nonWord = regexp.MustCompile(`[^a-z0-9]+`)

func normalize(s string) string {
	return " " + strings.TrimSpace(nonWord.ReplaceAllString(strings.ToLower(s), " ")) + " "
}

// Classify sets Technique and Tactic from an explicit ID or from keywords in
// the rule name and category.
func Classify(e *Event, hints ...string) {
	if e.Technique == "" {
		e.Technique = FindTechnique(hints...)
	}
	if e.Technique == "" {
		text := normalize(e.Rule + " " + strings.Join(hints, " "))
		for _, r := range keywordRules {
			if containsPhrase(text, r.phrases) {
				e.Technique = r.technique
				break
			}
		}
	}
	if t, ok := Techniques[e.Technique]; ok {
		e.Tactic = t.Tactic
	} else if base, _, ok := strings.Cut(e.Technique, "."); ok {
		if t, ok := Techniques[base]; ok {
			e.Tactic = t.Tactic
		}
	}
}

func containsPhrase(text string, phrases []string) bool {
	for _, p := range phrases {
		if strings.Contains(text, " "+p+" ") {
			return true
		}
	}
	return false
}
