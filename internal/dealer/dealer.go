// Package dealer is the trusted-dealer key ceremony for Shoup threshold RSA.
//
// Trust assumption (explicit, see docs/KEY_CEREMONY.md): the dealer process
// sees the full RSA key while generating it. It never writes the full private
// key anywhere; it emits only public metadata and one share per signer.
package dealer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/keyshare"
)

// MetaFileName and ShareFileName are the output file names.
const MetaFileName = "public-meta.json"

// ShareFileName returns share-<i>.json.
func ShareFileName(i int) string { return fmt.Sprintf("share-%d.json", i) }

// Key is the output of one ceremony, held in memory only.
type Key struct {
	Meta   *keymeta.File
	Shares []*keyshare.File
}

// Generate creates a t-of-n Shoup RSA key with a modulus of exactly
// modulusBits bits.
//
// tcrsa.NewKey(b) yields a (b-1)-bit modulus (NOTES.md N3), so b =
// modulusBits+1 is passed and the result is checked.
func Generate(modulusBits, t, n int) (*Key, error) {
	if modulusBits < keymeta.MinModulusBits {
		return nil, fmt.Errorf("modulus %d bits < minimum %d", modulusBits, keymeta.MinModulusBits)
	}
	if n < 2 || n > 64 || t < n/2+1 || t > n {
		return nil, fmt.Errorf("invalid threshold %d of %d (tcrsa requires n/2+1 <= t <= n)", t, n)
	}
	shares, meta, err := tcrsa.NewKey(modulusBits+1, uint16(t), uint16(n), nil)
	if err != nil {
		return nil, fmt.Errorf("tcrsa.NewKey: %w", err)
	}
	if got := meta.PublicKey.N.BitLen(); got != modulusBits {
		return nil, fmt.Errorf("generated modulus is %d bits, want %d", got, modulusBits)
	}
	mf, err := keymeta.FromTcrsa(meta, time.Now())
	if err != nil {
		return nil, err
	}
	k := &Key{Meta: mf}
	for _, s := range shares {
		k.Shares = append(k.Shares, keyshare.FromTcrsa(s, mf.KID))
	}
	return k, nil
}

// Output describes one written artifact, for the ceremony transcript.
type Output struct {
	Name   string // file path or vault path
	SHA256 string // hex SHA-256 of the exact bytes written
}

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func fingerprint(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// writeExclusive creates path with mode and fails if it already exists.
func writeExclusive(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// O_CREATE honours umask; force the exact mode.
	return os.Chmod(path, mode)
}

// WriteMeta writes public-meta.json (0644) into dir. It never overwrites.
func WriteMeta(dir string, k *Key) (Output, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Output{}, err
	}
	b, err := marshal(k.Meta)
	if err != nil {
		return Output{}, err
	}
	p := filepath.Join(dir, MetaFileName)
	if err := writeExclusive(p, b, 0o644); err != nil {
		return Output{}, fmt.Errorf("write %s: %w", p, err)
	}
	return Output{Name: p, SHA256: fingerprint(b)}, nil
}

// WriteShareFiles writes share-<i>.json (0600) into dir, one share per file.
func WriteShareFiles(dir string, k *Key) ([]Output, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var outs []Output
	for _, s := range k.Shares {
		b, err := marshal(s)
		if err != nil {
			return nil, err
		}
		p := filepath.Join(dir, ShareFileName(s.SignerIndex))
		if err := writeExclusive(p, b, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", p, err)
		}
		outs = append(outs, Output{Name: p, SHA256: fingerprint(b)})
	}
	return outs, nil
}

// WriteVault writes each share to a Vault KV v2 mount at
// <mount>/frost-k8s/signer-<i>, e.g. secret/frost-k8s/signer-3.
func WriteVault(ctx context.Context, client *http.Client, addr, token, mount string, k *Key) ([]Output, error) {
	if addr == "" || token == "" || mount == "" {
		return nil, errors.New("vault: VAULT_ADDR, VAULT_TOKEN and mount are all required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	var outs []Output
	for _, s := range k.Shares {
		payload, err := json.Marshal(map[string]any{"data": s})
		if err != nil {
			return nil, err
		}
		kv := keyshare.VaultPath(s.SignerIndex)
		url := strings.TrimRight(addr, "/") + "/v1/" + mount + "/data/" + kv
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Vault-Token", token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("vault write %s: %w", kv, err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("vault write %s/%s: HTTP %d", mount, kv, resp.StatusCode)
		}
		b, _ := json.Marshal(s)
		outs = append(outs, Output{Name: "vault:" + mount + "/" + kv, SHA256: fingerprint(b)})
	}
	return outs, nil
}
