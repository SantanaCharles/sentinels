// Command feedsign manages the Ed25519 key that signs the emergency advisory
// feed. It is a maintainer tool and is not shipped in releases.
//
//	feedsign keygen -out ~/.sentinels/feed-signing.key   # once; prints the public key
//	feedsign sign   -key ~/.sentinels/feed-signing.key internal/intel/advisories.json
//	feedsign verify internal/intel/advisories.json       # uses the key built into Sentinels
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/ai"
	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/intel"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		out := fs.String("out", "", "arquivo da chave privada (será criado com permissão 0600)")
		fs.Parse(os.Args[2:])
		if *out == "" {
			usage()
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		check(err)
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		check(err) // O_EXCL: never overwrite an existing key
		_, err = f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
		check(err)
		check(f.Close())
		fmt.Printf("chave privada: %s (guarde fora do repositório)\nchave pública: %s\n", *out, base64.StdEncoding.EncodeToString(pub))
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		keyPath := fs.String("key", "", "arquivo da chave privada")
		fs.Parse(os.Args[2:])
		if *keyPath == "" || fs.NArg() != 1 {
			usage()
		}
		seedB64, err := os.ReadFile(*keyPath)
		check(err)
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedB64)))
		if err != nil || len(seed) != ed25519.SeedSize {
			fail("chave privada inválida")
		}
		priv := ed25519.NewKeyFromSeed(seed)
		data, err := os.ReadFile(fs.Arg(0))
		check(err)
		var probe []intel.Advisory
		if err := json.Unmarshal(data, &probe); err != nil {
			fail("o arquivo não é um feed válido: " + err.Error()) // never sign something agents would reject
		}
		check(os.WriteFile(fs.Arg(0)+intel.SigSuffix, intel.SignFeed(data, priv), 0o644))
		if intel.VerifyFeed(data, intel.SignFeed(data, priv), base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))) != nil {
			fail("verificação pós-assinatura falhou")
		}
		fmt.Printf("assinado: %s%s (%d alerta(s))\n", fs.Arg(0), intel.SigSuffix, len(probe))
	case "draft":
		os.Exit(draft(os.Args[2:]))
	case "verify":
		if len(os.Args) != 3 {
			usage()
		}
		data, err := os.ReadFile(os.Args[2])
		check(err)
		sig, err := os.ReadFile(os.Args[2] + intel.SigSuffix)
		check(err)
		if err := intel.VerifyFeed(data, sig, intel.FeedPublicKey); err != nil {
			fail(err.Error() + " — rode `feedsign sign` depois de editar o feed")
		}
		fmt.Println("assinatura válida")
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "uso: feedsign keygen -out <arquivo> | sign -key <arquivo> <feed.json> | verify <feed.json> | draft -in <arquivo|https://…> [-config sentinels.yaml] [-out rascunho.json]")
	os.Exit(2)
}

// draft asks the configured AI to turn an advisory into a feed entry. The
// result is only written to -out (or printed): adding it to the feed and
// signing stay manual, after human review.
func draft(args []string) int {
	fs := flag.NewFlagSet("draft", flag.ExitOnError)
	in := fs.String("in", "", "aviso de segurança: arquivo de texto ou URL https")
	cfgPath := fs.String("config", "/etc/sentinels/sentinels.yaml", "configuração com a seção ai")
	out := fs.String("out", "", "grava o rascunho neste arquivo (padrão: só mostra)")
	fs.Parse(args)
	if *in == "" {
		usage()
	}
	source, err := readSource(*in)
	check(err)
	if len(strings.TrimSpace(source)) < 200 {
		fail(ai.ErrNoSource.Error())
	}
	cfg, err := config.Load(*cfgPath, true)
	check(err)
	cfg.AI.Enabled = true // maintainer tool: the agent's ai.enabled does not apply
	p, err := ai.New(cfg.AI)
	check(err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	a, problems, err := ai.DraftAdvisory(ctx, p, source)
	check(err)
	b, _ := json.MarshalIndent(a, "", "  ")
	if *out != "" {
		check(os.WriteFile(*out, append(b, '\n'), 0o644))
		fmt.Printf("rascunho gravado em %s\n", *out)
	} else {
		fmt.Println(string(b))
	}
	if len(problems) > 0 {
		fmt.Fprintln(os.Stderr, "\nProblemas encontrados — corrija antes de incluir no feed:")
		for _, pr := range problems {
			fmt.Fprintln(os.Stderr, "  -", pr)
		}
		return 1
	}
	fmt.Fprintln(os.Stderr, "\nValidação ok. Revise o texto, inclua em internal/intel/advisories.json e rode `feedsign sign`.")
	return 0
}

var tagRe = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]+>`)

// readSource loads a file or an https page (HTML reduced to text).
func readSource(in string) (string, error) {
	if !strings.HasPrefix(in, "http://") && !strings.HasPrefix(in, "https://") {
		b, err := os.ReadFile(in)
		return string(b), err
	}
	if !strings.HasPrefix(in, "https://") {
		return "", fmt.Errorf("use https")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(in)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %d", in, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return "", err
	}
	text := html.UnescapeString(tagRe.ReplaceAllString(string(b), " "))
	text = strings.Join(strings.Fields(text), " ")
	return "Fonte: " + in + "\n\n" + text, nil
}

func check(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "erro:", msg)
	os.Exit(1)
}
