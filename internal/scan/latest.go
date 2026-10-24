package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ErrNoScan means no report exists yet in the report directory.
var ErrNoScan = errors.New("nenhuma varredura encontrada ainda; a primeira roda alguns minutos depois que o agente inicia (ou: sentinels scan)")

// Latest loads the newest report-*.json from dir.
func Latest(dir string) (*Result, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "report-*.json"))
	if len(files) == 0 {
		return nil, ErrNoScan
	}
	sort.Strings(files) // timestamped names sort chronologically
	b, err := os.ReadFile(files[len(files)-1])
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("relatório ilegível: %w", err)
	}
	return &r, nil
}
