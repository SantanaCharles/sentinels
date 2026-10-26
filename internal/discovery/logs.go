package discovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LogLine is one line written by a container to stdout or stderr.
type LogLine struct {
	Time time.Time
	Text string
}

// Logs returns what the container wrote after since, reading at most
// maxBytes; truncated reports that there was more. Read-only (GET), allowed
// by the socket proxy with CONTAINERS=1.
func (c *Client) Logs(ctx context.Context, id string, since time.Time, tty bool, maxBytes int64) (lines []LogLine, truncated bool, err error) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"},
		"since": {fmt.Sprintf("%d.%09d", since.Unix(), since.Nanosecond())}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+url.PathEscape(id)+"/logs?"+q.Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("API do Docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("API do Docker /logs: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > maxBytes {
		body, truncated = body[:maxBytes], true
	}
	if !tty {
		body = demux(body)
	}
	text := string(body)
	if truncated {
		if i := strings.LastIndexByte(text, '\n'); i >= 0 {
			text = text[:i] // drop the cut line
		}
	}
	for _, l := range strings.Split(text, "\n") {
		ts, rest, ok := strings.Cut(strings.TrimRight(l, "\r"), " ")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		lines = append(lines, LogLine{Time: t, Text: rest})
	}
	return lines, truncated, nil
}

// demux joins the payloads of Docker's multiplexed stream: each frame has an
// 8-byte header (stream, 0, 0, 0, big-endian size).
func demux(b []byte) []byte {
	var out bytes.Buffer
	for len(b) >= 8 {
		size := int(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
		if size > len(b) {
			size = len(b)
		}
		out.Write(b[:size])
		b = b[size:]
	}
	return out.Bytes()
}
