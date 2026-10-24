package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// TelegramChat is a conversation the bot has seen, offered by setup so the
// administrator does not need to find the chat_id by hand.
type TelegramChat struct {
	ID    string
	Label string
}

// TelegramChats reads the bot's pending updates (the admin sends any message
// to the bot first) and returns the distinct chats. apiBase "" = api.telegram.org.
func TelegramChats(ctx context.Context, token, apiBase string) ([]TelegramChat, error) {
	if apiBase == "" {
		apiBase = "https://api.telegram.org"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/bot"+token+"/getUpdates?limit=100", nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, redact(err, apiBase+"/bot"+token+"/getUpdates?limit=100")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var doc struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      []struct {
			Message     *tgMessage `json:"message"`
			ChannelPost *tgMessage `json:"channel_post"`
			MyChat      *struct {
				Chat tgChat `json:"chat"`
			} `json:"my_chat_member"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("resposta inesperada do Telegram (HTTP %d)", resp.StatusCode)
	}
	if !doc.OK {
		return nil, fmt.Errorf("Telegram recusou o token: %s", Clean(doc.Description, 120))
	}
	seen := map[int64]bool{}
	var out []TelegramChat
	add := func(c tgChat) {
		if c.ID == 0 || seen[c.ID] {
			return
		}
		seen[c.ID] = true
		name := c.Title
		if name == "" {
			name = c.FirstName
			if c.Username != "" {
				name += " (@" + c.Username + ")"
			}
		}
		out = append(out, TelegramChat{ID: strconv.FormatInt(c.ID, 10), Label: Clean(name, 60) + " — " + c.Type})
	}
	for _, u := range doc.Result {
		switch {
		case u.Message != nil:
			add(u.Message.Chat)
		case u.ChannelPost != nil:
			add(u.ChannelPost.Chat)
		case u.MyChat != nil:
			add(u.MyChat.Chat)
		}
	}
	return out, nil
}

type tgMessage struct {
	Chat tgChat `json:"chat"`
}

type tgChat struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
}
