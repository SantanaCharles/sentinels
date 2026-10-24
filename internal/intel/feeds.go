package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	KEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	EPSSURL = "https://api.first.org/data/v1/epss"

	maxFeedSize = 32 << 20
	epssBatch   = 80
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

type KEVEntry struct {
	CVE        string `json:"cveID"`
	DateAdded  string `json:"dateAdded"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

// KEV maps CVE ID to its catalog entry.
type KEV map[string]KEVEntry

func LoadKEV(ctx context.Context, cacheDir string) (KEV, error) {
	raw, err := cachedFetch(ctx, KEVURL, cacheDir, "kev.json", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("catálogo KEV inválido: %w", err)
	}
	kev := make(KEV, len(doc.Vulnerabilities))
	for _, e := range doc.Vulnerabilities {
		kev[e.CVE] = e
	}
	return kev, nil
}

// LoadEPSS returns the exploitation probability (0..1) for each CVE.
func LoadEPSS(ctx context.Context, cves []string) (map[string]float64, error) {
	out := make(map[string]float64, len(cves))
	for i := 0; i < len(cves); i += epssBatch {
		end := min(i+epssBatch, len(cves))
		u := EPSSURL + "?cve=" + url.QueryEscape(strings.Join(cves[i:end], ","))
		raw, err := fetch(ctx, u)
		if err != nil {
			return out, err
		}
		var doc struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return out, fmt.Errorf("resposta EPSS inválida: %w", err)
		}
		for _, d := range doc.Data {
			if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				out[d.CVE] = f
			}
		}
	}
	return out, nil
}

// cachedFetch returns the cached copy while it is fresher than ttl, and falls
// back to a stale copy when the download fails.
func cachedFetch(ctx context.Context, u, dir, name string, ttl time.Duration) ([]byte, error) {
	path := filepath.Join(dir, name)
	if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) < ttl {
		if b, err := os.ReadFile(path); err == nil {
			return b, nil
		}
	}
	b, err := fetch(ctx, u)
	if err != nil {
		if stale, rerr := os.ReadFile(path); rerr == nil {
			return stale, nil
		}
		return nil, err
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o750); err == nil {
			tmp := path + ".tmp"
			if os.WriteFile(tmp, b, 0o640) == nil {
				_ = os.Rename(tmp, path)
			}
		}
	}
	return b, nil
}

func fetch(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Sentinels/0.1 (+https://github.com/SantanaCharles/sentinels)")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFeedSize))
}
