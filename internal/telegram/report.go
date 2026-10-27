package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/version"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

// report answers /report: the previous full day by default, or the current
// day so far with "/report hoje". It reuses the daily-report formatter, so the
// text matches the scheduled report, including the attacks-by-country section.
func (b *Bot) report(ctx context.Context, args []string) reply {
	now := time.Now()
	var start, end time.Time
	var when string
	if len(args) > 0 && (strings.EqualFold(args[0], "hoje") || strings.EqualFold(args[0], "today")) {
		start = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		end = now
		when = "hoje até agora"
	} else {
		end = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		start = end.AddDate(0, 0, -1)
		when = start.Format("02/01/2006")
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "📅 Relatório — %s\n", when)
	for _, l := range watch.DailyReportLines(ctx, b.Store, b.GeoIP, start, end) {
		fmt.Fprintf(&sb, "• %s\n", l)
	}
	return reply{text: sb.String()}
}

// update answers /update: it checks the newest published release and compares
// it with the running version. It never applies anything — the bot stays
// read-only — it only reports and shows the command to run.
func (b *Bot) update(ctx context.Context) reply {
	cur := version.Version
	check := b.LatestRelease
	if check == nil {
		check = latestRelease
	}
	latest, err := check(ctx)
	if err != nil {
		return reply{text: "Não consegui consultar a última versão no GitHub agora (" + err.Error() + ").\nVocê está rodando a " + cur + "."}
	}
	if sameVersion(cur, latest) {
		return reply{text: fmt.Sprintf("✅ Você está na última versão (%s).", cur)}
	}
	return reply{text: fmt.Sprintf("⬆️ Versão nova disponível: %s (você está na %s).\n\n"+
		"Para atualizar na VPS (Docker):\n"+
		"docker compose pull sentinels && docker compose up -d sentinels\n"+
		"No Portainer: Recreate com \"Pull latest image\".\n\n"+
		"O bot não atualiza sozinho — só avisa.", latest, cur)}
}

// latestRelease reads the newest release tag from the GitHub API.
func latestRelease(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/SantanaCharles/sentinels/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Sentinels")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", err
	}
	if body.TagName == "" {
		return "", fmt.Errorf("resposta sem tag_name")
	}
	return body.TagName, nil
}

// sameVersion compares ignoring a leading "v". A development build (…-dev) is
// never considered up to date, so /update is useful while testing too.
func sameVersion(cur, latest string) bool {
	norm := func(s string) string {
		return strings.TrimPrefix(strings.TrimSpace(strings.ToLower(s)), "v")
	}
	c := norm(cur)
	if strings.Contains(c, "dev") {
		return false
	}
	return c == norm(latest)
}
