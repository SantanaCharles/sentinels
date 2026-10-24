package intel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The shipped feed must verify with the key built into the binary, or every
// installed agent would reject it.
func TestShippedFeedIsSigned(t *testing.T) {
	sig, err := os.ReadFile("advisories.json" + SigSuffix)
	if err != nil {
		t.Fatal("advisories.json.sig ausente: rode `go run ./cmd/feedsign sign`")
	}
	if err := VerifyFeed(embeddedAdvisories, sig, FeedPublicKey); err != nil {
		t.Fatalf("feed embutido não confere com a assinatura: %v — rode `feedsign sign` após editar", err)
	}
}

type testFeed struct {
	data, sig []byte
	down      bool
}

func withTestKey(t *testing.T) (ed25519.PrivateKey, *testFeed, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	oldKey, oldURL := FeedPublicKey, advisoryFeedURL
	FeedPublicKey = base64.StdEncoding.EncodeToString(pub)
	feed := &testFeed{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case feed.down:
			w.WriteHeader(http.StatusBadGateway)
		case r.URL.Path == "/feed.json":
			w.Write(feed.data)
		case r.URL.Path == "/feed.json.sig":
			w.Write(feed.sig)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	advisoryFeedURL = srv.URL + "/feed.json"
	t.Cleanup(func() { FeedPublicKey, advisoryFeedURL = oldKey, oldURL; srv.Close() })
	return priv, feed, t.TempDir()
}

const newAdvisory = `[{"id":"novo-2026-11","title":"Falha nova","product":"nginx","severity":"critical","fixed":{"1.27":"1.27.9"}}]`

func ids(advs []Advisory) map[string]bool {
	m := map[string]bool{}
	for _, a := range advs {
		m[a.ID] = true
	}
	return m
}

func TestSignedFeedAccepted(t *testing.T) {
	priv, feed, dir := withTestKey(t)
	feed.data = []byte(newAdvisory)
	feed.sig = SignFeed(feed.data, priv)
	advs, err := LoadAdvisories(context.Background(), dir, false)
	if err != nil || !ids(advs)["novo-2026-11"] || !ids(advs)["php2shell-2026-10"] {
		t.Fatalf("feed assinado: %v %v", ids(advs), err)
	}
	// Feed goes down: the verified cache keeps working even when stale.
	feed.down = true
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(filepath.Join(dir, "advisories.json"), old, old)
	advs, err = LoadAdvisories(context.Background(), dir, false)
	if err != nil || !ids(advs)["novo-2026-11"] {
		t.Errorf("cache verificado não usado: %v %v", ids(advs), err)
	}
}

func TestTamperedFeedRejected(t *testing.T) {
	priv, feed, dir := withTestKey(t)
	feed.sig = SignFeed([]byte(newAdvisory), priv)
	feed.data = []byte(`[{"id":"falso","title":"Alerta injetado","product":"php","severity":"critical"}]`)
	advs, err := LoadAdvisories(context.Background(), dir, false)
	if err == nil || ids(advs)["falso"] {
		t.Fatalf("feed adulterado aceito: %v", ids(advs))
	}
	if !ids(advs)["php2shell-2026-10"] {
		t.Error("lista embutida perdida após rejeitar o feed")
	}
	if _, err := os.Stat(filepath.Join(dir, "advisories.json")); err == nil {
		t.Error("conteúdo não verificado foi para o cache")
	}

	// A signature from another key is just as invalid.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	feed.data = []byte(newAdvisory)
	feed.sig = SignFeed(feed.data, other)
	if advs, err := LoadAdvisories(context.Background(), dir, false); err == nil || ids(advs)["novo-2026-11"] {
		t.Error("assinatura de outra chave aceita")
	}

	// A tampered cache file is ignored too.
	os.MkdirAll(dir, 0o750)
	os.WriteFile(filepath.Join(dir, "advisories.json"), []byte(`[{"id":"falso"}]`), 0o640)
	os.WriteFile(filepath.Join(dir, "advisories.json.sig"), SignFeed([]byte(newAdvisory), priv), 0o640)
	feed.down = true
	if advs, _ := LoadAdvisories(context.Background(), dir, false); ids(advs)["falso"] {
		t.Error("cache adulterado aceito")
	}
}
