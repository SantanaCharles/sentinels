package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/version"
)

const defaultConfig = "/etc/sentinels/sentinels.yaml"

const usage = `Sentinels — agente de segurança para servidores e containers

Uso:
  sentinels <comando> [opções]

Comandos:
  setup     assistente de configuração (menus no terminal) — comece por aqui
  config    show | get | set | set-secret, para scripts
  scan      varredura completa e relatório
  watch     monitoramento contínuo, correlação e alertas
  events    lista os eventos guardados na memória local
  feedback  marca um evento como falso positivo (fp) ou ataque confirmado
  suppressions  lista ou remove silenciamentos de falso positivo
  findings  lista achados abertos (chaves para o accept)
  accept    aceita o risco de um achado, com justificativa
  notify-test   envia um alerta de teste para os notificadores
  explain   análise da IA de um evento guardado
  ai-test   testa a conexão com a IA e lista as skills
  mcp       servidor MCP somente leitura (Claude, ChatGPT e outros clientes)
  doctor    verifica integrações disponíveis
  version   mostra a versão

Execute "sentinels <comando> -h" para ver as opções.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(ctx, os.Args[2:]))
	case "watch":
		os.Exit(runWatch(ctx, os.Args[2:]))
	case "events":
		os.Exit(runEvents(ctx, os.Args[2:]))
	case "feedback":
		os.Exit(runFeedback(ctx, os.Args[2:]))
	case "suppressions":
		os.Exit(runSuppressions(ctx, os.Args[2:]))
	case "findings":
		os.Exit(runFindings(ctx, os.Args[2:]))
	case "accept":
		os.Exit(runAccept(ctx, os.Args[2:]))
	case "notify-test":
		os.Exit(runNotifyTest(ctx, os.Args[2:]))
	case "explain":
		os.Exit(runExplain(ctx, os.Args[2:]))
	case "ai-test":
		os.Exit(runAITest(ctx, os.Args[2:]))
	case "mcp":
		os.Exit(runMCP(ctx, os.Args[2:]))
	case "setup":
		os.Exit(runSetup(ctx, os.Args[2:]))
	case "config":
		os.Exit(runConfig(ctx, os.Args[2:]))
	case "doctor":
		os.Exit(runDoctor(ctx, os.Args[2:]))
	case "version":
		fmt.Printf("sentinels %s (%s)\n", version.Version, version.Commit)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "comando desconhecido: %s\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

// loadConfig registers -config, parses args and loads the file. The default
// path is optional so every command works with zero configuration.
func loadConfig(fs *flag.FlagSet, args []string) (config.Config, error) {
	path := fs.String("config", defaultConfig, "arquivo de configuração")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	return config.Load(*path, !explicit)
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
