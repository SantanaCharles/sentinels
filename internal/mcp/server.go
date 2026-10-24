// Package mcp is a minimal, read-only Model Context Protocol server: it
// exposes tools over JSON-RPC 2.0, on stdio (newline-delimited) or on the
// Streamable HTTP transport (single JSON responses, no SSE).
package mcp

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unicode/utf8"
)

// Protocol versions this server speaks, newest first.
var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

type Tool struct {
	Name        string
	Title       string
	Description string
	InputSchema map[string]any
	Handler     func(ctx context.Context, args json.RawMessage) (string, error)
}

type Server struct {
	Name         string
	Version      string
	Instructions string
	Tools        []Tool
	Log          func(format string, args ...any)
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const (
	errParse          = -32700
	errInvalidRequest = -32600
	errMethodNotFound = -32601
	errInvalidParams  = -32602

	maxMessage = 1 << 20
	maxOutput  = 60 << 10
)

// Handle processes one JSON-RPC message. Notifications return nil.
func (s *Server) Handle(ctx context.Context, raw []byte) []byte {
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return encode(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{errParse, "JSON inválido"}})
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return encode(response{JSONRPC: "2.0", ID: idOrNull(req.ID), Error: &rpcError{errInvalidRequest, "requisição JSON-RPC inválida"}})
	}
	if len(req.ID) == 0 {
		return nil // notification (e.g. notifications/initialized): no reply
	}
	result, rerr := s.dispatch(ctx, req)
	return encode(response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr})
}

func (s *Server) dispatch(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		version := protocolVersions[0]
		for _, v := range protocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": s.Name, "title": "Sentinels", "version": s.Version},
			"instructions":    s.Instructions,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools := make([]map[string]any, 0, len(s.Tools))
		for _, t := range s.Tools {
			tools = append(tools, map[string]any{
				"name": t.Name, "title": t.Title, "description": t.Description, "inputSchema": t.InputSchema,
				"annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
			})
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{errInvalidParams, "params.name obrigatório"}
		}
		for _, t := range s.Tools {
			if t.Name != p.Name {
				continue
			}
			args := p.Arguments
			if len(args) == 0 || string(args) == "null" {
				args = json.RawMessage("{}")
			}
			text, err := t.Handler(ctx, args)
			if err != nil {
				// Tool failures are results the model can read, not protocol errors.
				return map[string]any{"content": []map[string]any{{"type": "text", "text": "Erro: " + err.Error()}}, "isError": true}, nil
			}
			if len(text) > maxOutput {
				cut := maxOutput
				for cut > 0 && !utf8.RuneStart(text[cut]) {
					cut--
				}
				text = text[:cut] + "\n… (resultado truncado; use filtros ou um limite menor)"
			}
			return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": false}, nil
		}
		return nil, &rpcError{errInvalidParams, fmt.Sprintf("ferramenta desconhecida: %s", p.Name)}
	}
	return nil, &rpcError{errMethodNotFound, "método não suportado: " + req.Method}
}

// ServeStdio reads newline-delimited messages until in closes. Nothing but
// protocol messages is ever written to out.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), maxMessage)
	var mu sync.Mutex
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if resp := s.Handle(ctx, []byte(line)); resp != nil {
			mu.Lock()
			out.Write(append(resp, '\n'))
			mu.Unlock()
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	return sc.Err()
}

// HTTPHandler serves the Streamable HTTP transport at any path. Every request
// needs "Authorization: Bearer <token>"; browser requests from foreign origins
// are refused (DNS rebinding protection).
func (s *Server) HTTPHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && !loopbackOrigin(o) {
			http.Error(w, "origem não permitida", http.StatusForbidden)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="sentinels"`)
			http.Error(w, "não autorizado", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxMessage))
		if err != nil {
			http.Error(w, "corpo inválido", http.StatusBadRequest)
			return
		}
		resp := s.Handle(r.Context(), body)
		if resp == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	})
}

func loopbackOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func encode(r response) []byte {
	b, _ := json.Marshal(r)
	return b
}

func idOrNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}
