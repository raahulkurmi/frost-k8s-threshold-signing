// Package keyshare holds exactly ONE secret threshold RSA key share.
//
// Only the signer and the dealer may import this package. The coordinator
// must not (invariant I3, enforced by TestCoordinatorHasNoSecretTypes).
package keyshare

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/keymeta"
)

// FormatVersion is the share-N.json schema version.
const FormatVersion = 1

// File is one signer's share as stored on disk (share-N.json) or in Vault.
type File struct {
	Version     int    `json:"version"`
	KID         string `json:"kid"`
	SignerIndex int    `json:"signer_index"`
	// Si is the secret share value, base64 std.
	Si string `json:"si"`
}

// FromTcrsa converts one tcrsa key share into its file form.
func FromTcrsa(s *tcrsa.KeyShare, kid string) *File {
	return &File{
		Version:     FormatVersion,
		KID:         kid,
		SignerIndex: int(s.Id),
		Si:          base64.StdEncoding.EncodeToString(s.Si),
	}
}

// Load reads share-N.json and validates it against meta and expectedIndex.
func Load(path string, meta *keymeta.Meta, expectedIndex int) (*tcrsa.KeyShare, error) {
	if path == "" {
		return nil, errors.New("keyshare: path is empty")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyshare: %w", err)
	}
	s, err := Parse(b, meta, expectedIndex)
	if err != nil {
		return nil, fmt.Errorf("keyshare: %s: %w", path, err)
	}
	return s, nil
}

// Parse decodes one share and checks, fail closed:
//   - schema version, no unknown fields, a single object;
//   - signer_index == expectedIndex and within [1, n];
//   - kid == meta.KID;
//   - the share is cryptographically bound to its public verification key:
//     v^si mod N == vk_i. A share for another index, another key, or a
//     corrupted value is rejected before the signer starts serving.
func Parse(b []byte, meta *keymeta.Meta, expectedIndex int) (*tcrsa.KeyShare, error) {
	if meta == nil {
		return nil, errors.New("meta is nil")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON object (a share file holds exactly one share)")
	}
	return f.validate(meta, expectedIndex)
}

func (f *File) validate(meta *keymeta.Meta, expectedIndex int) (*tcrsa.KeyShare, error) {
	if f.Version != FormatVersion {
		return nil, fmt.Errorf("version %d, want %d", f.Version, FormatVersion)
	}
	if expectedIndex < 1 || expectedIndex > meta.Parties {
		return nil, fmt.Errorf("expected signer index %d outside [1,%d]", expectedIndex, meta.Parties)
	}
	if f.SignerIndex != expectedIndex {
		return nil, fmt.Errorf("share is for signer %d, this is signer %d", f.SignerIndex, expectedIndex)
	}
	if f.KID != meta.KID {
		return nil, fmt.Errorf("share kid %q does not match meta kid %q", f.KID, meta.KID)
	}
	si, err := base64.StdEncoding.DecodeString(f.Si)
	if err != nil || len(si) == 0 {
		return nil, errors.New("si: missing or bad base64")
	}
	n := meta.PublicKey.N
	v := new(big.Int).SetBytes(meta.Tcrsa.VerificationKey.V)
	want := new(big.Int).SetBytes(meta.Tcrsa.VerificationKey.I[expectedIndex-1])
	if got := new(big.Int).Exp(v, new(big.Int).SetBytes(si), n); got.Cmp(want) != 0 {
		return nil, errors.New("share does not match its verification key (wrong key, index or corrupted)")
	}
	return &tcrsa.KeyShare{Si: si, Id: uint16(expectedIndex)}, nil
}

// VaultPath returns the KV path for a signer's share: frost-k8s/signer-<i>
// under the given KV v2 mount (default "secret").
func VaultPath(index int) string { return fmt.Sprintf("frost-k8s/signer-%d", index) }

// LoadFromVault reads a signer's share from a Vault KV v2 mount, e.g.
// GET {addr}/v1/secret/data/frost-k8s/signer-3. Any error is fatal.
func LoadFromVault(ctx context.Context, addr, token, mount string, meta *keymeta.Meta, expectedIndex int) (*tcrsa.KeyShare, error) {
	if addr == "" || token == "" || mount == "" {
		return nil, errors.New("keyshare: vault address, token and mount are all required")
	}
	u, err := url.Parse(strings.TrimRight(addr, "/") + "/v1/" + mount + "/data/" + VaultPath(expectedIndex))
	if err != nil {
		return nil, fmt.Errorf("keyshare: vault url: %w", err)
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
		return nil, fmt.Errorf("keyshare: vault request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("keyshare: vault read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keyshare: vault %s returned HTTP %d", u.Path, resp.StatusCode)
	}
	var env struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("keyshare: vault response: %w", err)
	}
	if len(env.Data.Data) == 0 || string(env.Data.Data) == "null" {
		return nil, fmt.Errorf("keyshare: vault %s has no data", u.Path)
	}
	s, err := Parse(env.Data.Data, meta, expectedIndex)
	if err != nil {
		return nil, fmt.Errorf("keyshare: vault %s: %w", u.Path, err)
	}
	return s, nil
}
