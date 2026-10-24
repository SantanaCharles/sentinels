// Package telegram lets administrators talk to the agent from Telegram:
// commands, feedback buttons on alerts and free-form questions answered by
// the configured AI.
//
// The bot long-polls the Bot API (no inbound port), answers only the
// configured chats, and can only read data and record feedback: it never
// changes containers, firewall rules or anything else on the server.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SantanaCharles/sentinels/internal/ai"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/store"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

type Bot struct {
	Token        string
	AllowedChats map[string]bool
	APIBase      string // tests only; default https://api.telegram.org
	Store        *store.Store
	ReportDir    string
	Host         string
	Analyst      *ai.Analyst // nil: free-form questions are disabled
	MaxAIPerHour int
	Scanner      Scanner // nil: /scan is unavailable
	Log          func(format string, args ...any)

	client   *http.Client
	offset   int64
	runCtx   context.Context
	mu       sync.Mutex
	aiWindow time.Time
	aiCalls  int
	warned   map[string]bool
	waiting  map[int64]bool // chats waiting for the end of a scan
}

// Scanner is the part of the watcher the bot can drive.
type Scanner interface {
	RequestScan() watch.ScanRequest
	Scanning() bool
}

// ScanDone is registered as a watcher AfterScan hook: chats that asked for a
// scan (or for a status before the first one finished) get the new status.
func (b *Bot) ScanDone(_ *scan.Result) {
	b.mu.Lock()
	chats := b.waiting
	b.waiting = nil
	ctx := b.runCtx
	b.mu.Unlock()
	if ctx == nil {
		return
	}
	for chatID := range chats {
		st := b.status(ctx)
		b.send(ctx, chatID, "✅ Varredura concluída.\n\n"+st.text, nil)
	}
}

func (b *Bot) waitForScan(chatID int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.waiting == nil {
		b.waiting = map[int64]bool{}
	}
	b.waiting[chatID] = true
}

// Run polls until ctx ends, backing off on errors.
func (b *Bot) Run(ctx context.Context) error {
	if b.APIBase == "" {
		b.APIBase = "https://api.telegram.org"
	}
	if b.Log == nil {
		b.Log = func(string, ...any) {}
	}
	b.client = &http.Client{Timeout: 70 * time.Second}
	b.mu.Lock()
	b.warned = map[string]bool{}
	b.runCtx = ctx
	b.mu.Unlock()
	b.registerCommands(ctx)
	if err := b.skipBacklog(ctx); err != nil {
		b.Log("telegram: %v", err)
	}
	b.Log("telegram: conversa ativa para %d chat(s)", len(b.AllowedChats))

	backoff := 5 * time.Second
	for ctx.Err() == nil {
		updates, err := b.getUpdates(ctx, 50)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			b.Log("telegram: %v (nova tentativa em %s)", err, backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 5*time.Minute)
			continue
		}
		backoff = 5 * time.Second
		for _, u := range updates {
			b.offset = u.UpdateID + 1
			b.handle(ctx, u)
		}
	}
	return nil
}

type update struct {
	UpdateID int64    `json:"update_id"`
	Message  *message `json:"message"`
	Callback *struct {
		ID      string   `json:"id"`
		From    user     `json:"from"`
		Message *message `json:"message"`
		Data    string   `json:"data"`
	} `json:"callback_query"`
}

type message struct {
	MessageID int64  `json:"message_id"`
	From      *user  `json:"from"`
	Chat      chat   `json:"chat"`
	Text      string `json:"text"`
}

type user struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
}

func (u user) name() string {
	if u.Username != "" {
		return "@" + u.Username
	}
	return u.FirstName
}

type chat struct {
	ID int64 `json:"id"`
}

func (b *Bot) allowed(chatID int64) bool {
	id := strconv.FormatInt(chatID, 10)
	if b.AllowedChats[id] {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.warned[id] { // log once per chat, so a spammer cannot flood the log
		b.warned[id] = true
		b.Log("telegram: mensagem ignorada do chat %s (não autorizado)", id)
	}
	return false
}

func (b *Bot) handle(ctx context.Context, u update) {
	switch {
	case u.Callback != nil:
		cb := u.Callback
		if cb.Message == nil || !b.allowed(cb.Message.Chat.ID) {
			b.answerCallback(ctx, cb.ID, "Não autorizado")
			return
		}
		text := b.onButton(ctx, cb.Message.Chat.ID, cb.Message.MessageID, cb.Data, cb.From)
		b.answerCallback(ctx, cb.ID, text)
	case u.Message != nil && u.Message.Text != "":
		m := u.Message
		if !b.allowed(m.Chat.ID) {
			return
		}
		for _, part := range split(b.onMessage(ctx, m)) {
			b.send(ctx, m.Chat.ID, part.text, part.buttons)
		}
	}
}

// --- Bot API ---------------------------------------------------------------

type apiResponse struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	ErrorCode   int             `json:"error_code"`
	Result      json.RawMessage `json:"result"`
}

func (b *Bot) call(ctx context.Context, method string, params any, out any) error {
	body, _ := json.Marshal(params)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.APIBase+"/bot"+b.Token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		// Never log the token: Go's error includes the URL.
		return fmt.Errorf("%s: %s", method, strings.ReplaceAll(err.Error(), b.Token, "<token>"))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var r apiResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("%s: resposta inválida (HTTP %d)", method, resp.StatusCode)
	}
	if !r.OK {
		if r.ErrorCode == http.StatusConflict {
			if strings.Contains(strings.ToLower(r.Description), "webhook") {
				return errors.New("este bot tem um webhook ativo (ex.: Telegram Trigger do n8n) e por isso não pode ser lido pelo agente: crie um bot só para o Sentinels no @BotFather")
			}
			return errors.New("outro processo está lendo este bot (getUpdates): use um bot por servidor ou ative a conversa em só um agente")
		}
		return fmt.Errorf("%s: %s", method, r.Description)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (b *Bot) getUpdates(ctx context.Context, timeout int) ([]update, error) {
	var ups []update
	err := b.call(ctx, "getUpdates", map[string]any{
		"offset": b.offset, "timeout": timeout, "allowed_updates": []string{"message", "callback_query"},
	}, &ups)
	return ups, err
}

// skipBacklog ignores messages sent while the agent was down: answering a
// stale "/status" or a stale button press would be confusing.
func (b *Bot) skipBacklog(ctx context.Context) error {
	var ups []update
	if err := b.call(ctx, "getUpdates", map[string]any{"offset": -1, "timeout": 0}, &ups); err != nil {
		return err
	}
	if len(ups) > 0 {
		b.offset = ups[len(ups)-1].UpdateID + 1
	}
	return nil
}

func (b *Bot) registerCommands(ctx context.Context) {
	cmds := []map[string]string{
		{"command": "status", "description": "Server summary"},
		{"command": "scan", "description": "Full scan now (status when it finishes)"},
		{"command": "findings", "description": "Open findings (e.g. /findings critical)"},
		{"command": "events", "description": "Recent attacks and events (e.g. /events 48)"},
		{"command": "event", "description": "Event details (e.g. /event 12)"},
		{"command": "muted", "description": "Active false-positive rules"},
		{"command": "help", "description": "How to use"},
	}
	if err := b.call(ctx, "setMyCommands", map[string]any{"commands": cmds}, nil); err != nil {
		b.Log("telegram: não consegui registrar o menu de comandos: %v", err)
	}
}

// Button is one inline keyboard button.
type Button struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

func (b *Bot) send(ctx context.Context, chatID int64, text string, buttons []Button) {
	params := map[string]any{"chat_id": chatID, "text": text, "disable_web_page_preview": true}
	if len(buttons) > 0 {
		params["reply_markup"] = map[string]any{"inline_keyboard": [][]Button{buttons}}
	}
	if err := b.call(ctx, "sendMessage", params, nil); err != nil {
		b.Log("telegram: %v", err)
	}
}

func (b *Bot) answerCallback(ctx context.Context, id, text string) {
	_ = b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
}

func (b *Bot) typing(ctx context.Context, chatID int64) {
	_ = b.call(ctx, "sendChatAction", map[string]any{"chat_id": chatID, "action": "typing"}, nil)
}

// clearButtons removes the keyboard of an alert once feedback was given.
func (b *Bot) clearButtons(ctx context.Context, chatID, messageID int64) {
	_ = b.call(ctx, "editMessageReplyMarkup", map[string]any{
		"chat_id": chatID, "message_id": messageID, "reply_markup": map[string]any{"inline_keyboard": [][]Button{}},
	}, nil)
}

type chunk struct {
	text    string
	buttons []Button
}

// reply is what a handler returns: text plus optional buttons.
type reply struct {
	text    string
	buttons []Button
}

const maxText = 3900 // Telegram limit is 4096

// split breaks long replies on line boundaries; buttons go on the last part.
func split(r reply) []chunk {
	if len(r.text) <= maxText {
		return []chunk{{r.text, r.buttons}}
	}
	var out []chunk
	var cur strings.Builder
	for _, line := range strings.Split(r.text, "\n") {
		if cur.Len()+len(line)+1 > maxText && cur.Len() > 0 {
			out = append(out, chunk{text: cur.String()})
			cur.Reset()
		}
		if len(line) > maxText {
			line = line[:maxText]
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
	}
	out = append(out, chunk{cur.String(), r.buttons})
	return out
}
