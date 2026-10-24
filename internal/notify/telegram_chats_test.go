package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTelegramChats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/bot123:ok/getUpdates") {
			w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
			return
		}
		w.Write([]byte(`{"ok":true,"result":[
			{"message":{"chat":{"id":555,"type":"private","first_name":"Charles","username":"charles"}}},
			{"message":{"chat":{"id":555,"type":"private","first_name":"Charles"}}},
			{"channel_post":{"chat":{"id":-1001234,"type":"channel","title":"Alertas TI"}}},
			{"my_chat_member":{"chat":{"id":-1009,"type":"supergroup","title":"Equipe\nfalsa"}}}
		]}`))
	}))
	defer srv.Close()
	chats, err := TelegramChats(context.Background(), "123:ok", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(chats) != 3 || chats[0].ID != "555" || !strings.Contains(chats[0].Label, "@charles") || chats[1].ID != "-1001234" {
		t.Errorf("conversas: %+v", chats)
	}
	if strings.Contains(chats[2].Label, "\n") {
		t.Error("título com quebra de linha não foi limpo")
	}
	if _, err := TelegramChats(context.Background(), "999:ruim", srv.URL); err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("token recusado: %v", err)
	}
}
