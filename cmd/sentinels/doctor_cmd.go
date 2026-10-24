package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/discovery"
	"github.com/SantanaCharles/sentinels/internal/integrations"
	"github.com/SantanaCharles/sentinels/internal/store"
)

func runDoctor(ctx context.Context, args []string) int {
	cfg, err := loadConfig(flag.NewFlagSet("doctor", flag.ExitOnError), args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	check := func(name string, ok bool, hint string) {
		mark := "ok   "
		if !ok {
			mark = "FALTA"
		}
		fmt.Printf("[%s] %-10s %s\n", mark, name, hint)
	}

	dockerErr := discovery.NewClient(cfg.Docker.Socket).Ping(ctx)
	check("docker", dockerErr == nil, cfg.Docker.Socket)

	p, ok := integrations.TrivyAvailable()
	if !ok {
		p = "instale: https://trivy.dev — CVEs das imagens"
	}
	check("trivy", ok, p)

	in := cfg.Integrations
	key := config.Secret(in.CrowdSec.APIKeyEnv)
	if key == "" {
		check("crowdsec", false, "defina "+in.CrowdSec.APIKeyEnv+" (`cscli bouncers add sentinels`) — https://crowdsec.net")
	} else {
		check("crowdsec", true, in.CrowdSec.URL)
	}

	_, err = os.Stat(in.Suricata.EveLog)
	hint := in.Suricata.EveLog
	if err != nil {
		hint += " não encontrado — https://suricata.io"
	}
	check("suricata", err == nil, hint)

	falcoOK := falcoInstalled() && integrations.IsLoopback(in.Falco.Listen)
	hint = "http_output → http://" + in.Falco.Listen + "/falco"
	if !falcoInstalled() {
		hint = "não instalado — https://falco.org"
	}
	check("falco", falcoOK, hint)

	hint = cfg.Storage.Path
	if st, err := store.Open(cfg.Storage.Path); err != nil {
		check("memória", false, hint+": "+err.Error())
	} else {
		st.Close()
		check("memória", true, hint)
	}

	for _, db := range cfg.Databases {
		check("db:"+db.Name, config.Secret(db.DSNEnv) != "", "variável "+db.DSNEnv)
	}
	if dockerErr != nil {
		return 1
	}
	return 0
}
