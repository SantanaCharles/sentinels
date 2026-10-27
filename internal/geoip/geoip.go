// Package geoip resolves attacker IPs to a country for the daily report.
//
// It reads a MaxMind-format database (.mmdb) entirely offline: the GeoLite2
// file that CrowdSec already installs, or the DB-IP Lite Country base that
// `sentinels setup install` can download. No IP ever leaves the machine.
package geoip

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// DB answers country lookups from one .mmdb file. A nil *DB is valid and
// always returns "unknown", so callers never need to nil-check it.
type DB struct {
	r    *maxminddb.Reader
	path string
}

// DefaultPaths lists where a country database is usually found, most
// preferred first: an explicit path from the config, CrowdSec's GeoLite2
// (present when CrowdSec was installed with geoip), then the file
// `setup install` writes next to the agent's own database.
func DefaultPaths(explicit, dataDir string) []string {
	var p []string
	if explicit != "" {
		p = append(p, explicit)
	}
	p = append(p,
		"/var/lib/crowdsec/data/GeoLite2-City.mmdb",
		"/var/lib/crowdsec/data/GeoLite2-Country.mmdb",
	)
	if dataDir != "" {
		p = append(p, filepath.Join(dataDir, "dbip-country.mmdb"))
	}
	return p
}

// Open opens the first readable database among paths. It returns (nil, nil)
// when none exists: country grouping is then simply unavailable and the
// daily report falls back to grouping by IP.
func Open(paths ...string) (*DB, error) {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		r, err := maxminddb.Open(p)
		if err != nil {
			return nil, fmt.Errorf("geoip %s: %w", p, err)
		}
		return &DB{r: r, path: p}, nil
	}
	return nil, nil
}

// Path reports which database file is in use.
func (d *DB) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// Close releases the database.
func (d *DB) Close() error {
	if d == nil || d.r == nil {
		return nil
	}
	return d.r.Close()
}

// Country returns the ISO 3166-1 code (e.g. "BR") and English name for ip.
// It returns "", "" for a private/loopback/invalid address, an IP missing
// from the database, or no database at all.
func (d *DB) Country(ip string) (code, name string) {
	if d == nil || d.r == nil {
		return "", ""
	}
	addr := net.ParseIP(ip)
	if addr == nil || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return "", ""
	}
	var rec struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
	}
	if err := d.r.Lookup(addr, &rec); err != nil {
		return "", ""
	}
	return rec.Country.ISOCode, rec.Country.Names["en"]
}

// Flag turns an ISO country code into its flag emoji ("BR" → 🇧🇷). An empty or
// malformed code yields the globe 🌐, so a line always renders.
func Flag(code string) string {
	if len(code) != 2 {
		return "🌐"
	}
	code = strings.ToUpper(code)
	r := make([]rune, 0, 2)
	for i := 0; i < 2; i++ {
		c := code[i]
		if c < 'A' || c > 'Z' {
			return "🌐"
		}
		r = append(r, rune(0x1F1E6+int(c-'A')))
	}
	return string(r)
}
