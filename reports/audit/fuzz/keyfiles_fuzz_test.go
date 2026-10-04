//go:build auditfuzz

package fuzz

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/dealer"
	"frost-k8s-threshold-signing/internal/grpcserver"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/keyshare"
	"frost-k8s-threshold-signing/internal/prioritykey"
)

func metaFileBytes(t testing.TB, fx *keyFx) []byte {
	b, err := os.ReadFile(filepath.Join(fx.Dir, dealer.MetaFileName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func timed(t *testing.T, limit time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	start := time.Now()
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s hung > 5s", what)
	}
	if el := time.Since(start); el > limit {
		t.Fatalf("%s took %v", what, el)
	}
}

// FuzzKeymetaParse: keymeta.Parse on public-meta.json bytes. Oracles: no
// panic/hang; an accepted meta is internally consistent (kid matches PKIX,
// >= 2048-bit modulus, honest-majority threshold, residues in [2, n-1]).
func FuzzKeymetaParse(f *testing.F) {
	fx := loadKey(f)
	good := metaFileBytes(f, fx)
	f.Add(good)
	var m map[string]any
	_ = json.Unmarshal(good, &m)
	mut := func(fn func(map[string]any)) []byte {
		c := map[string]any{}
		_ = json.Unmarshal(good, &c)
		fn(c)
		return mustJSON(f, c)
	}
	f.Add(mut(func(c map[string]any) { c["threshold"] = 2 }))
	f.Add(mut(func(c map[string]any) { c["threshold"] = 5; c["parties"] = 5 }))
	f.Add(mut(func(c map[string]any) { c["parties"] = 64; c["threshold"] = 33 }))
	f.Add(mut(func(c map[string]any) { c["kid"] = "AAAAAAAAAAAAAAAAAAAAAA" }))
	f.Add(mut(func(c map[string]any) { c["modulus_bits"] = 1024 }))
	f.Add(mut(func(c map[string]any) { c["version"] = 2 }))
	f.Add(mut(func(c map[string]any) { c["algorithm"] = "PS256" }))
	f.Add(mut(func(c map[string]any) { c["created_at"] = "0001-01-01T00:00:00Z" }))
	f.Add(mut(func(c map[string]any) {
		vk := c["verification_key"].(map[string]any)
		vk["v"] = base64.StdEncoding.EncodeToString([]byte{1})
	}))
	f.Add(mut(func(c map[string]any) {
		vk := c["verification_key"].(map[string]any)
		vk["i"] = vk["i"].([]any)[:4]
	}))
	f.Add(mut(func(c map[string]any) { c["extra"] = true }))
	f.Add(append(append([]byte(nil), good...), []byte(`{}`)...))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var mm *keymeta.Meta
		var err error
		timed(t, 2*time.Second, "keymeta.Parse", func() { mm, err = keymeta.Parse(b) })
		if err != nil {
			return
		}
		if mm.PublicKey.N.BitLen() < keymeta.MinModulusBits || mm.KID != keymeta.ComputeKID(mm.PKIX) ||
			mm.Threshold < mm.Parties/2+1 || mm.Threshold > mm.Parties || mm.Parties > 64 ||
			len(mm.Tcrsa.VerificationKey.I) != mm.Parties || int(mm.Tcrsa.L) != mm.Parties || int(mm.Tcrsa.K) != mm.Threshold {
			t.Fatalf("Parse accepted inconsistent meta")
		}
		n := mm.PublicKey.N
		chk := func(v []byte) {
			x := new(big.Int).SetBytes(v)
			if x.Cmp(big.NewInt(2)) < 0 || x.Cmp(n) >= 0 {
				t.Fatalf("residue out of range accepted")
			}
		}
		chk(mm.Tcrsa.VerificationKey.V)
		chk(mm.Tcrsa.VerificationKey.U)
		for _, v := range mm.Tcrsa.VerificationKey.I {
			chk(v)
		}
	})
}

// FuzzKeyshareParse: keyshare.Parse(bytes, meta, idx). Oracles: no panic/hang
// (si is attacker-sized: big.Int.Exp cost grows with len(si)); an accepted
// share satisfies v^si = vk_idx (recomputed here) and produces a share that
// verifies.
func FuzzKeyshareParse(f *testing.F) {
	fx := loadKey(f)
	for i := 1; i <= 5; i++ {
		b, err := os.ReadFile(filepath.Join(fx.Dir, dealer.ShareFileName(i)))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, uint8(i))
		if i == 1 {
			f.Add(b, uint8(2))
			f.Add(b, uint8(0))
			f.Add(b, uint8(6))
			var c map[string]any
			_ = json.Unmarshal(b, &c)
			si, _ := base64.StdEncoding.DecodeString(c["si"].(string))
			c2 := map[string]any{}
			for k, v := range c {
				c2[k] = v
			}
			c2["si"] = base64.StdEncoding.EncodeToString(append([]byte{0, 0}, si...))
			f.Add(mustJSON(f, c2), uint8(1))
			c2["si"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 4096))
			f.Add(mustJSON(f, c2), uint8(1))
			c2["si"] = ""
			f.Add(mustJSON(f, c2), uint8(1))
			c2["signer_index"] = 2
			f.Add(mustJSON(f, c2), uint8(1))
			f.Add(append(append([]byte(nil), b...), b...), uint8(1))
			f.Add([]byte(strings.Replace(string(b), `"version"`, `"Version"`, 1)), uint8(1))
		}
	}
	meta := fx.Meta
	n := meta.PublicKey.N
	f.Fuzz(func(t *testing.T, b []byte, idx uint8) {
		var err error
		var got = new(big.Int)
		var si []byte
		var sid uint16
		timed(t, 2*time.Second, "keyshare.Parse", func() {
			s, e := keyshare.Parse(b, meta, int(idx))
			err = e
			if e == nil {
				si, sid = s.Si, s.Id
			}
		})
		if err != nil {
			return
		}
		if int(sid) != int(idx) || idx < 1 || int(idx) > meta.Parties {
			t.Fatalf("accepted share id %d for idx %d", sid, idx)
		}
		v := new(big.Int).SetBytes(meta.Tcrsa.VerificationKey.V)
		got.Exp(v, new(big.Int).SetBytes(si), n)
		if got.Cmp(new(big.Int).SetBytes(meta.Tcrsa.VerificationKey.I[idx-1])) != 0 {
			t.Fatalf("accepted share with v^si != vk_%d", idx)
		}
		doc := paddedDigest(t, meta, "fuzz-doc")
		ks2 := *fx.Shares[idx-1]
		ks2.Si = si
		ss, err := ks2.Sign(doc, crypto.SHA256, meta.Tcrsa)
		if err != nil {
			t.Fatal(err)
		}
		if err := ss.Verify(doc, meta.Tcrsa); err != nil {
			t.Fatalf("accepted share signs an unverifiable share: %v", err)
		}
	})
}

// FuzzPriorityKeyParse: prioritykey.Parse(bytes, kid). Oracles: no panic;
// accepted key is exactly prioritykey.Size bytes.
func FuzzPriorityKeyParse(f *testing.F) {
	pf, err := prioritykey.Generate(seedKID)
	if err != nil {
		f.Fatal(err)
	}
	good := mustJSON(f, pf)
	f.Add(good, seedKID)
	f.Add(good, "other")
	f.Add([]byte(strings.Replace(string(good), `"version":1`, `"version":2`, 1)), seedKID)
	f.Add([]byte(`{"version":1,"kid":"`+seedKID+`","priority_key":"`+base64.StdEncoding.EncodeToString(make([]byte, 31))+`"}`), seedKID)
	f.Add([]byte(`{"version":1,"kid":"`+seedKID+`","priority_key":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`","x":1}`), seedKID)
	f.Add(append(append([]byte(nil), good...), good...), seedKID)
	f.Add([]byte(`{"version":1,"kid":"","priority_key":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`"}`), "")
	f.Fuzz(func(t *testing.T, b []byte, kid string) {
		k, err := prioritykey.Parse(b, kid)
		if err == nil && len(k) != prioritykey.Size {
			t.Fatalf("accepted %d-byte key", len(k))
		}
	})
}

// FuzzTimingInterceptor: grpcserver.TimingInterceptor with fuzzed nginx
// metadata. Oracles: no panic; values are attached only when well-formed.
func FuzzTimingInterceptor(f *testing.F) {
	f.Add("0123456789abcdef0123456789abcdef", "1790000000.250", "", false)
	f.Add("not-hex", "12.5", "", false)
	f.Add("0123456789ABCDEF0123456789ABCDEF", "1790000000.25x", "", true)
	f.Add("0123456789abcdef0123456789abcdef", "9999999999.999", "0123456789abcdef0123456789abcdef", true)
	f.Add("0123456789abcdef0123456789abcdef\n", "1790000000.250\n", "", false)
	f.Add("", "0000000000.000", "", false)
	f.Add("\xff", "\x00", "\xff", true)
	f.Fuzz(func(t *testing.T, id, msec, id2 string, deadline bool) {
		md := metadata.MD{}
		md.Append(grpcserver.HeaderNginxRequestID, id)
		md.Append(grpcserver.HeaderNginxMsec, msec)
		if id2 != "" {
			md.Append(grpcserver.HeaderNginxRequestID, id2)
		}
		ctx := metadata.NewIncomingContext(context.Background(), md)
		if deadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Second)
			defer cancel()
		}
		var got coordinator.Arrival
		_, err := grpcserver.TimingInterceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
			a, ok := coordinator.ArrivalFrom(ctx)
			if !ok {
				t.Fatal("no Arrival")
			}
			got = a
			return nil, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if got.NginxRequestID != "" && (got.NginxRequestID != id || id2 != "" || len(id) != 32) {
			t.Fatalf("request id %q attached from %q/%q", got.NginxRequestID, id, id2)
		}
		if !got.NginxProxyAt.IsZero() && len(msec) != 14 {
			t.Fatalf("msec %q attached as %v", msec, got.NginxProxyAt)
		}
	})
}
