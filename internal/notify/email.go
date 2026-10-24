package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Email sends plain-text mail. Port 465 uses implicit TLS; any other port
// requires STARTTLS unless the server is on loopback, so credentials never
// travel in clear text.
type Email struct {
	Host     string // host:port
	User     string
	Password string
	From     string
	To       []string
}

func (e *Email) Name() string { return "email" }

func (e *Email) Send(ctx context.Context, m Message) error {
	from, err := mail.ParseAddress(e.From)
	if err != nil {
		return fmt.Errorf("from inválido: %w", err)
	}
	var to []string
	for _, addr := range e.To {
		a, err := mail.ParseAddress(addr)
		if err != nil {
			return fmt.Errorf("destinatário inválido %q: %w", addr, err)
		}
		to = append(to, a.Address)
	}
	if len(to) == 0 {
		return errors.New("nenhum destinatário (to)")
	}
	msg, err := buildMail(from, to, Subject(m), Text(m))
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- e.deliver(from.Address, to, msg) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Email) deliver(from string, to []string, msg []byte) error {
	host, port, err := net.SplitHostPort(e.Host)
	if err != nil {
		return fmt.Errorf("smtp_host deve ser host:porta: %w", err)
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	var conn net.Conn
	if port == "465" {
		conn, err = tls.DialWithDialer(dialer, "tcp", e.Host, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", e.Host)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()

	if port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS: %w", err)
			}
		} else if !isLoopbackHost(host) {
			return errors.New("servidor SMTP sem STARTTLS; recusando enviar sem criptografia")
		}
	}
	if e.User != "" {
		// PlainAuth itself refuses to send credentials without TLS, except to localhost.
		if err := c.Auth(smtp.PlainAuth("", e.User, e.Password, host)); err != nil {
			return fmt.Errorf("autenticação SMTP: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// buildMail writes RFC 5322 headers (subject Q-encoded, already free of CR/LF)
// and a quoted-printable UTF-8 body.
func buildMail(from *mail.Address, to []string, subject, body string) ([]byte, error) {
	var b bytes.Buffer
	id := make([]byte, 12)
	rand.Read(id)
	domain := from.Address[strings.LastIndex(from.Address, "@")+1:]
	fmt.Fprintf(&b, "From: %s\r\n", from.String())
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), domain)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
