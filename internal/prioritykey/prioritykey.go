// Package prioritykey holds the signers' shared admission-priority key
// K_prio (NOTES N76, docs/PRIORITY_ADMISSION.md). The dealer generates it with
// the threshold key and every signer receives the same copy; the coordinator
// never does, so it cannot compute a request's priority.
//
// K_prio is not signing material: a leak lets its holder predict admission
// priorities, nothing more (docs/PRIORITY_ADMISSION.md §4). It is still
// handled like a secret (0600, never in an image, never on the coordinator
// host). Only the signer and the dealer may import this package (T12).
package prioritykey

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// FileName is the dealer's output file name.
const FileName = "priority.key"

// FormatVersion is the priority.key schema version.
const FormatVersion = 1

// Size is the key length in bytes.
const Size = 32

// File is priority.key as stored on disk.
type File struct {
	Version int    `json:"version"`
	KID     string `json:"kid"`          // the threshold key it was generated with
	Key     string `json:"priority_key"` // base64 std, Size bytes
}

// Generate returns a fresh key file bound to kid.
func Generate(kid string) (*File, error) {
	if kid == "" {
		return nil, errors.New("prioritykey: kid is required")
	}
	b := make([]byte, Size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &File{Version: FormatVersion, KID: kid, Key: base64.StdEncoding.EncodeToString(b)}, nil
}

// Load reads priority.key and returns the key. It fails closed on a wrong
// version, a kid other than wantKID, unknown fields or a key of the wrong size.
func Load(path, wantKID string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("prioritykey: %w", err)
	}
	k, err := Parse(b, wantKID)
	if err != nil {
		return nil, fmt.Errorf("prioritykey: %s: %w", path, err)
	}
	return k, nil
}

// Parse decodes and validates one priority key file.
func Parse(b []byte, wantKID string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON object")
	}
	if f.Version != FormatVersion {
		return nil, fmt.Errorf("version %d, want %d", f.Version, FormatVersion)
	}
	if f.KID != wantKID {
		return nil, fmt.Errorf("kid %q does not match the key's kid %q", f.KID, wantKID)
	}
	k, err := base64.StdEncoding.DecodeString(f.Key)
	if err != nil || len(k) != Size {
		return nil, fmt.Errorf("priority_key: want %d bytes of base64", Size)
	}
	return k, nil
}

// VaultPath is the KV path of the priority key under a KV v2 mount.
const VaultPath = "frost-k8s/priority-key"

// LoadFromVault reads the priority key from a Vault KV v2 mount
// (GET {addr}/v1/<mount>/data/frost-k8s/priority-key). Any error is fatal.
func LoadFromVault(ctx context.Context, addr, token, mount, wantKID string) ([]byte, error) {
	if addr == "" || token == "" || mount == "" {
		return nil, errors.New("prioritykey: vault address, token and mount are all required")
	}
	u, err := url.Parse(strings.TrimRight(addr, "/") + "/v1/" + mount + "/data/" + VaultPath)
	if err != nil {
		return nil, fmt.Errorf("prioritykey: vault url: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prioritykey: vault request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("prioritykey: vault read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prioritykey: vault %s returned HTTP %d", u.Path, resp.StatusCode)
	}
	var env struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data.Data) == 0 || string(env.Data.Data) == "null" {
		return nil, fmt.Errorf("prioritykey: vault %s has no data", u.Path)
	}
	k, err := Parse(env.Data.Data, wantKID)
	if err != nil {
		return nil, fmt.Errorf("prioritykey: vault %s: %w", u.Path, err)
	}
	return k, nil
}
