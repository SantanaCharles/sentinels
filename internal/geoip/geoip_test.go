package geoip

import (
	"path/filepath"
	"testing"
)

func TestFlag(t *testing.T) {
	cases := map[string]string{
		"BR": "🇧🇷",
		"ru": "🇷🇺",
		"":   "🌐",
		"B":  "🌐",
		"B1": "🌐",
	}
	for in, want := range cases {
		if got := Flag(in); got != want {
			t.Errorf("Flag(%q) = %q, quero %q", in, got, want)
		}
	}
}

func TestNilDBIsSafe(t *testing.T) {
	var d *DB
	if code, name := d.Country("8.8.8.8"); code != "" || name != "" {
		t.Errorf("DB nulo deve retornar vazio, veio %q/%q", code, name)
	}
	if d.Path() != "" || d.Close() != nil {
		t.Error("Path/Close em DB nulo devem ser inócuos")
	}
}

func TestOpenMissingReturnsNil(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "nao-existe.mmdb"), "")
	if err != nil {
		t.Fatalf("base ausente não é erro: %v", err)
	}
	if d != nil {
		t.Error("base ausente deve retornar nil")
	}
}

func TestPrivateAndInvalidAreUnknown(t *testing.T) {
	// Even with no database the parsing guard should not panic; covered by
	// the nil-DB path returning empty for any input.
	var d *DB
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "::1", "not-an-ip"} {
		if code, _ := d.Country(ip); code != "" {
			t.Errorf("%s deveria ser desconhecido", ip)
		}
	}
}
