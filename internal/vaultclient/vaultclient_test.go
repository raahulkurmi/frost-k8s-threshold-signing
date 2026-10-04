package vaultclient_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"frost-k8s-threshold-signing/internal/dealer"
	"frost-k8s-threshold-signing/internal/keyshare"
	"frost-k8s-threshold-signing/internal/prioritykey"
	"frost-k8s-threshold-signing/internal/vaultclient"
)

const token = "test-vault-token-not-a-secret"

// collector records anything that reaches the redirect target.
type collector struct {
	mu     sync.Mutex
	hits   int
	tokens []string
	bodies []string
}

func (c *collector) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.hits++
	c.tokens = append(c.tokens, r.Header.Get("X-Vault-Token"))
	c.bodies = append(c.bodies, string(b))
	c.mu.Unlock()
	w.WriteHeader(http.StatusNotFound)
}

// redirector answers every request with a 307 to target (same path).
func redirector(t *testing.T, target string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// otherHosts returns redirect targets that differ from the redirector's
// origin: another host name for the same listener, and another port.
func otherHosts(t *testing.T, col *collector) map[string]string {
	t.Helper()
	other := httptest.NewServer(http.HandlerFunc(col.handler))
	t.Cleanup(other.Close)
	u, _ := url.Parse(other.URL)
	return map[string]string{
		"other host name": "http://localhost:" + u.Port(),
		"other port":      other.URL,
	}
}

// TestNoCrossHostRedirect (audit E-1): neither the signer's share read, its
// priority-key read, nor the dealer's share and priority-key writes follow a
// redirect off the configured Vault origin, so the token and the secret share
// never reach the redirect target.
func TestNoCrossHostRedirect(t *testing.T) {
	col := &collector{}
	k := &dealer.Key{Shares: []*keyshare.File{{Version: 1, KID: "kid", SignerIndex: 1, Si: "c2VjcmV0LXNoYXJlLXZhbHVl"}}}
	for name, target := range otherHosts(t, col) {
		vault := redirector(t, target)
		calls := map[string]func() error{
			"keyshare.LoadFromVault": func() error {
				_, err := keyshare.LoadFromVault(context.Background(), vault.URL, token, "secret", nil, 1)
				return err
			},
			"prioritykey.LoadFromVault": func() error {
				_, err := prioritykey.LoadFromVault(context.Background(), vault.URL, token, "secret", "kid")
				return err
			},
			"dealer.WriteVault (nil client)": func() error {
				_, err := dealer.WriteVault(context.Background(), nil, vault.URL, token, "secret", k)
				return err
			},
			"dealer.WriteVault (caller client)": func() error {
				_, err := dealer.WriteVault(context.Background(), &http.Client{}, vault.URL, token, "secret", k)
				return err
			},
		}
		for call, f := range calls {
			err := f()
			if err == nil || !strings.Contains(err.Error(), "refusing redirect") {
				t.Errorf("%s, %s: err = %v, want a refused redirect", name, call, err)
			}
		}
	}
	col.mu.Lock()
	defer col.mu.Unlock()
	if col.hits != 0 {
		t.Fatalf("redirect target received %d requests (tokens %q, bodies %q)", col.hits, col.tokens, col.bodies)
	}
}

// TestSameOriginRedirectFollowed: a redirect within the configured Vault
// origin (Vault's own standby forwarding) still works and carries the token.
func TestSameOriginRedirectFollowed(t *testing.T) {
	var got string
	mux := http.NewServeMux()
	mux.HandleFunc("/moved/", func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Vault-Token")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/moved"+r.URL.Path, http.StatusTemporaryRedirect)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	k := &dealer.Key{Shares: []*keyshare.File{{Version: 1, KID: "kid", SignerIndex: 1, Si: "c2VjcmV0LXNoYXJlLXZhbHVl"}}}
	if _, err := dealer.WriteVault(context.Background(), nil, srv.URL, token, "secret", k); err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Fatalf("same-origin redirect target got token %q", got)
	}
}

func TestGuardKeepsCallerSettings(t *testing.T) {
	c := &http.Client{Timeout: 3}
	g := vaultclient.Guard(c, 10)
	if g == c || g.Timeout != 3 || g.CheckRedirect == nil || c.CheckRedirect != nil {
		t.Fatalf("Guard: %+v (caller client mutated: %v)", g, c.CheckRedirect != nil)
	}
}
