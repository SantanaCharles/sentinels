package discovery

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogsDemuxAndTimestamps(t *testing.T) {
	frame := func(s string) []byte {
		h := []byte{2, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
		return append(h, s...)
	}
	var since string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/containers/abc/logs" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		since = r.URL.Query().Get("since")
		w.Write(frame("2026-10-25T11:35:01.000000001Z ERROR:  primeira\n"))
		w.Write(frame("2026-10-25T11:35:02.5Z STATEMENT:  SELECT 1\n"))
	}))
	defer srv.Close()
	c := NewClient("tcp://" + strings.TrimPrefix(srv.URL, "http://"))

	lines, trunc, err := c.Logs(context.Background(), "abc", time.Unix(1700000000, 5), false, 1<<20)
	if err != nil || trunc || len(lines) != 2 || lines[1].Text != "STATEMENT:  SELECT 1" || lines[0].Time.Nanosecond() != 1 {
		t.Fatalf("logs: %v %v %+v", err, trunc, lines)
	}
	if since != "1700000000.000000005" {
		t.Errorf("since = %s", since)
	}

	// Over the limit: the cut line is dropped and truncation reported.
	lines, trunc, _ = c.Logs(context.Background(), "abc", time.Now(), false, 70)
	if !trunc || len(lines) != 1 {
		t.Errorf("limite: %v %+v", trunc, lines)
	}
}
