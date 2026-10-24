package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

func TestRecordScanHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("permissão do banco = %v", fi.Mode().Perm())
		}
	}
	ctx := context.Background()
	t0 := time.Now()
	a := finding.Finding{ID: "x", Target: "db", Title: "A", Severity: finding.High}
	b := finding.Finding{ID: "y", Target: "db", Title: "B", Severity: finding.Low}

	d, err := st.RecordScan(ctx, t0, []finding.Finding{a, b})
	if err != nil || len(d.New) != 2 {
		t.Fatalf("primeira varredura: %+v %v", d, err)
	}
	d, _ = st.RecordScan(ctx, t0.Add(time.Hour), []finding.Finding{a})
	if len(d.New) != 0 || len(d.Resolved) != 1 || d.Resolved[0] != "B — db" {
		t.Errorf("segunda varredura: %+v", d)
	}
	d, _ = st.RecordScan(ctx, t0.Add(2*time.Hour), []finding.Finding{a, b})
	if len(d.New) != 1 || d.New[0].ID != "y" {
		t.Errorf("regressão não marcada como nova: %+v", d)
	}
}
