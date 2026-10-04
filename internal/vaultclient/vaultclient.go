// Package vaultclient builds the HTTP clients used for every Vault request
// (share and priority-key reads in the signer, writes in the dealer).
//
// Go's http.Client follows redirects and forwards custom headers such as
// X-Vault-Token, and for 307/308 also the request body, to the new location,
// even on another host. A Vault address that answers with a redirect could
// therefore collect the token and, from the dealer, a secret share (audit E-1).
// These clients follow a redirect only to the same scheme, host and port.
package vaultclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// maxRedirects bounds same-origin redirects (Vault itself does not redirect
// KV requests except standby-to-active forwarding).
const maxRedirects = 5

// CheckRedirect refuses any redirect that leaves the original request's
// scheme, host or port.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("vault: too many redirects")
	}
	orig := via[0].URL
	if req.URL.Scheme != orig.Scheme || req.URL.Host != orig.Host {
		return fmt.Errorf("vault: refusing redirect from %s://%s to %s://%s (token and body would leave the configured Vault address)",
			orig.Scheme, orig.Host, req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// New returns a client with the given timeout and the same-origin redirect policy.
func New(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: CheckRedirect}
}

// Guard returns a shallow copy of c (or New(timeout) if c is nil) whose
// redirect policy is CheckRedirect. A caller-supplied client never loses the
// guard.
func Guard(c *http.Client, timeout time.Duration) *http.Client {
	if c == nil {
		return New(timeout)
	}
	cp := *c
	cp.CheckRedirect = CheckRedirect
	return &cp
}

// DevAllowHTTPEnv names the explicit development flag that permits a
// plain-http Vault address. Only the exact value "1" enables it; any other
// non-empty value is an error, so a typo fails closed (audit E-1).
const DevAllowHTTPEnv = "VAULT_DEV_ALLOW_HTTP"

// CheckAddr requires an absolute https:// Vault address with a host. A plain
// http:// address is accepted only when allowHTTP is true (the dev flag): over
// http the token, and from the dealer the secret shares, would cross the
// network in the clear.
func CheckAddr(addr string, allowHTTP bool) error {
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("vault: VAULT_ADDR %q is not an absolute URL with a host", addr)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowHTTP {
			return nil
		}
		return fmt.Errorf("vault: VAULT_ADDR %q uses plain http; use https:// (set %s=1 only for local development)", addr, DevAllowHTTPEnv)
	}
	return fmt.Errorf("vault: VAULT_ADDR %q must use https://", addr)
}

// CheckAddrEnv applies CheckAddr with the dev flag read through getenv.
func CheckAddrEnv(addr string, getenv func(string) string) error {
	allow := false
	switch v := getenv(DevAllowHTTPEnv); v {
	case "":
	case "1":
		allow = true
	default:
		return fmt.Errorf("vault: %s=%q; only \"1\" is accepted", DevAllowHTTPEnv, v)
	}
	return CheckAddr(addr, allow)
}
