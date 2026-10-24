package intel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FeedPublicKey verifies the emergency advisory feed (Ed25519, base64).
// The private key stays with the maintainers; see docs/INSTALACAO.md for
// how the feed is signed and how the key is rotated.
var FeedPublicKey = "5tvGiY11pPv9y7PZCEgexgkbv5OmG74deW/h+M+qFqA="

// SigSuffix is appended to the feed URL and cache file for the signature.
const SigSuffix = ".sig"

var ErrBadSignature = errors.New("assinatura do feed inválida")

// VerifyFeed checks sig (base64 text) over data with the base64 public key.
func VerifyFeed(data, sig []byte, pubB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("chave pública do feed inválida no binário")
	}
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(s) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, s) {
		return ErrBadSignature
	}
	return nil
}

// SignFeed produces the signature file content for data (maintainers only).
func SignFeed(data []byte, priv ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)) + "\n")
}

// fetchSignedFeed returns the feed only when its signature verifies. A fresh
// verified cache is used as is; on download failure a stale verified cache is
// the fallback. Unverified content is never cached nor returned.
func fetchSignedFeed(ctx context.Context, url, dir, name string, ttl time.Duration) ([]byte, error) {
	path := filepath.Join(dir, name)
	readCache := func() ([]byte, bool) {
		data, err1 := os.ReadFile(path)
		sig, err2 := os.ReadFile(path + SigSuffix)
		if err1 != nil || err2 != nil || VerifyFeed(data, sig, FeedPublicKey) != nil {
			return nil, false
		}
		return data, true
	}
	if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) < ttl {
		if data, ok := readCache(); ok {
			return data, nil
		}
	}

	data, err := fetch(ctx, url)
	var sig []byte
	if err == nil {
		sig, err = fetch(ctx, url+SigSuffix)
	}
	if err == nil {
		err = VerifyFeed(data, sig, FeedPublicKey)
	}
	if err != nil {
		if cached, ok := readCache(); ok {
			return cached, nil
		}
		return nil, fmt.Errorf("feed %s: %w", url, err)
	}
	if dir != "" && os.MkdirAll(dir, 0o750) == nil {
		// Signature first: a crash between the writes leaves a pair that fails
		// verification instead of an unsigned feed.
		writeAtomic(path+SigSuffix, sig)
		writeAtomic(path, data)
	}
	return data, nil
}

func writeAtomic(path string, b []byte) {
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, path)
	}
}
