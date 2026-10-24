package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/mcp"
	"github.com/SantanaCharles/sentinels/internal/store"
	"github.com/SantanaCharles/sentinels/internal/version"
)

// sentinels mcp — read-only MCP server.
//
//	stdio (padrão): o cliente executa o comando, normalmente via ssh
//	--http 127.0.0.1:8765: Streamable HTTP com token obrigatório
func runMCP(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	httpAddr := fs.String("http", "", "servir via HTTP neste endereço (ex.: 127.0.0.1:8765) em vez de stdio")
	allowRemote := fs.Bool("allow-remote", false, "permitir --http fora de localhost (use TLS num proxy reverso na frente)")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	st, err := store.OpenReadOnly(cfg.Storage.Path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer st.Close()

	srv := &mcp.Server{
		Name: "sentinels", Version: version.Version, Instructions: mcp.Instructions,
		Tools: mcp.Tools(mcp.Deps{Store: st, ReportDir: cfg.Scan.ReportDir, KeepIPs: cfg.MCP.KeepIPs}),
	}

	if *httpAddr == "" {
		// stdout belongs to the protocol; diagnostics go to stderr only.
		if err := srv.ServeStdio(ctx, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "mcp:", err)
			return 1
		}
		return 0
	}

	token := config.Secret(cfg.MCP.TokenEnv)
	if len(token) < 24 {
		fmt.Fprintf(os.Stderr, "defina %s com um token aleatório de pelo menos 24 caracteres (ex.: openssl rand -hex 32)\n", cfg.MCP.TokenEnv)
		return 2
	}
	host, _, err := net.SplitHostPort(*httpAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "--http deve ser host:porta")
		return 2
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) && !*allowRemote {
		fmt.Fprintln(os.Stderr, "--http fora de localhost exige --allow-remote (e TLS num proxy reverso). Prefira túnel SSH.")
		return 2
	}
	hs := &http.Server{
		Addr: *httpAddr, Handler: srv.HTTPHandler(token),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	logf("MCP (somente leitura) em http://%s — %d ferramentas", *httpAddr, len(srv.Tools))
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
