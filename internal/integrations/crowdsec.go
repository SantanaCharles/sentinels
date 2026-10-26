package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

// CrowdSec polls the Local API decision stream with a bouncer key
// (`cscli bouncers add sentinels`). Only decisions produced by this machine's
// own detections are reported; community blocklists are ignored.
type CrowdSec struct {
	URL      string
	APIKey   string
	Interval time.Duration
	client   *http.Client

	mu     sync.Mutex
	active map[int64]Blocked // local decisions in force, for /blocked
	synced bool              // the startup snapshot was read
}

// Blocked is a decision currently enforced by CrowdSec on this server.
type Blocked struct {
	ID       int64
	Value    string // usually an IP; a range or country depending on Scope
	Scope    string
	Type     string // ban, captcha…
	Scenario string
	Origin   string // crowdsec (detected here) or cscli (manual)
	Until    time.Time
}

// maxTracked bounds memory if CrowdSec is flooded with decisions.
const maxTracked = 100_000

func (c *CrowdSec) Name() string { return "crowdsec" }

type csDecision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

// Local origins: "crowdsec" (scenario triggered here) and "cscli" (manual ban).
var localOrigins = map[string]bool{"crowdsec": true, "cscli": true}

func (c *CrowdSec) Run(ctx context.Context, out chan<- event.Event) error {
	if c.client == nil {
		c.client = &http.Client{Timeout: 30 * time.Second}
	}
	if c.Interval <= 0 {
		c.Interval = 10 * time.Second
	}
	startup := true
	seen := map[int64]bool{}
	tick := time.NewTicker(c.Interval)
	defer tick.Stop()
	for {
		decisions, deleted, err := c.poll(ctx, startup)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		c.track(decisions, deleted, time.Now())
		// Decisions active at startup were already handled by CrowdSec
		// before Sentinels started; only report what happens from now on.
		for _, d := range decisions {
			if seen[d.ID] || !localOrigins[d.Origin] {
				continue
			}
			seen[d.ID] = true
			if startup {
				continue
			}
			if !send(ctx, out, decisionEvent(d)) {
				return nil
			}
		}
		startup = false
		if len(seen) > 200_000 { // stream only returns new IDs; old ones can go
			seen = map[int64]bool{}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// track keeps the set of decisions in force: the stream sends each new
// decision once and lists it again under "deleted" when it expires or is removed.
func (c *CrowdSec) track(added, deleted []csDecision, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == nil {
		c.active = map[int64]Blocked{}
	}
	for _, d := range deleted {
		delete(c.active, d.ID)
	}
	for _, d := range added {
		if !localOrigins[d.Origin] || len(c.active) >= maxTracked {
			continue
		}
		left, err := time.ParseDuration(d.Duration)
		if err != nil || left <= 0 {
			continue
		}
		c.active[d.ID] = Blocked{ID: d.ID, Value: d.Value, Scope: d.Scope, Type: d.Type,
			Scenario: d.Scenario, Origin: d.Origin, Until: now.Add(left)}
	}
	c.synced = true
}

// Blocked returns the decisions in force, newest first; ok is false until
// the first answer from the Local API arrives.
func (c *CrowdSec) Blocked(now time.Time) (list []Blocked, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, b := range c.active {
		if !b.Until.After(now) {
			delete(c.active, id)
			continue
		}
		list = append(list, b)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID > list[j].ID })
	return list, c.synced
}

func (c *CrowdSec) poll(ctx context.Context, startup bool) (added, deleted []csDecision, err error) {
	u := strings.TrimRight(c.URL, "/") + fmt.Sprintf("/v1/decisions/stream?startup=%t&origins=crowdsec,cscli", startup)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("X-Api-Key", c.APIKey)
	req.Header.Set("User-Agent", "Sentinels/0.1")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("crowdsec: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("crowdsec: HTTP %d (verifique a chave do bouncer)", resp.StatusCode)
	}
	var body struct {
		New     []csDecision `json:"new"`
		Deleted []csDecision `json:"deleted"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&body); err != nil {
		return nil, nil, fmt.Errorf("crowdsec: resposta inválida: %w", err)
	}
	return body.New, body.Deleted, nil
}

func decisionEvent(d csDecision) event.Event {
	e := event.Event{
		Source:   "crowdsec",
		Rule:     d.Scenario,
		Severity: finding.High,
		Time:     time.Now(),
		Summary:  fmt.Sprintf("CrowdSec aplicou %s (%s) a %s %s pelo cenário %s", d.Type, d.Duration, d.Scope, d.Value, d.Scenario),
	}
	if strings.EqualFold(d.Scope, "ip") {
		e.SourceIP = d.Value
	}
	if raw, err := json.Marshal(d); err == nil {
		e.Raw = event.TrimRaw(raw)
	}
	event.Classify(&e)
	if e.Technique == "T1595" || e.Technique == "T1046" {
		e.Severity = finding.Medium // reconnaissance: noisy, already blocked
	}
	return e
}
