package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/keyshare"
	"frost-k8s-threshold-signing/internal/prioritykey"
	"frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/testutil"
)

type envMap map[string]string

func (e envMap) get(k string) string { return e[k] }

func baseEnv(t *testing.T, fx *testutil.Fixture, id int) envMap {
	t.Helper()
	pki := testutil.NewPKI(t)
	sc := pki.Signer(t, id)
	return envMap{
		"SIGNER_ID":   itoa(id),
		"META_FILE":   fx.MetaPath,
		"SHARE_FILE":  fx.SharePath(id),
		"POLICY_FILE": testutil.PolicyFile(t, t.TempDir(), testutil.PolicyConfig()),
		"AUDIT_LOG":   filepath.Join(t.TempDir(), "audit.log"),
		"TLS_CERT":    sc.Cert,
		"TLS_KEY":     sc.Key,
		"TLS_CA":      pki.CA,
	}
}

func itoa(i int) string { return string(rune('0' + i)) }

func mustFail(t *testing.T, e envMap, want string) {
	t.Helper()
	_, err := load(context.Background(), e.get)
	if err == nil {
		t.Fatalf("load succeeded, want error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
	t.Logf("refused: %v", err)
}

func rewriteShare(t *testing.T, src string, mut func(*keyshare.File)) string {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	var f keyshare.File
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	mut(&f)
	out, _ := json.Marshal(f)
	p := filepath.Join(t.TempDir(), "share.json")
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	fx := testutil.Key(t)
	s, err := load(context.Background(), baseEnv(t, fx, 4).get)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != 4 || int(s.Share.Id) != 4 || s.Meta.KID != fx.Meta.KID {
		t.Fatalf("loaded %+v", s)
	}
}

func writePriorityKey(t *testing.T, kid string) string {
	t.Helper()
	f, err := prioritykey.Generate(kid)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(f)
	p := filepath.Join(t.TempDir(), prioritykey.FileName)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// N76: SIGNER_ADMISSION=priority loads the shared key; default is n48; the
// deadline cap defaults to 4s and is configurable.
func TestLoadAdmissionModes(t *testing.T) {
	fx := testutil.Key(t)
	e := baseEnv(t, fx, 2)
	s, err := load(context.Background(), e.get)
	if err != nil || s.PrioKey != nil || s.MaxDL != 0 {
		t.Fatalf("default: err=%v prio=%v maxdl=%v, want n48 and the built-in cap", err, s.PrioKey != nil, s.MaxDL)
	}
	e["SIGNER_ADMISSION"], e["PRIORITY_KEY_FILE"], e["SIGNER_MAX_DEADLINE"] = "priority", writePriorityKey(t, fx.Meta.KID), "3s"
	s, err = load(context.Background(), e.get)
	if err != nil || len(s.PrioKey) != prioritykey.Size || s.MaxDL.String() != "3s" {
		t.Fatalf("priority: err=%v key=%d maxdl=%v", err, len(s.PrioKey), s.MaxDL)
	}
	if s.Adm.Mode != signer.PriorityStable || s.Adm.Epoch != 0 || s.Adm.Rotation != 0 || s.Adm.Controller != "v2" {
		t.Fatalf("priority default: %+v, want stable with the built-in epoch and rotation", s.Adm)
	}
	e["SIGNER_PRIORITY"], e["SIGNER_PRIORITY_EPOCH"], e["SIGNER_PRIORITY_ROTATION"] = "request", "30s", "64"
	if s, err = load(context.Background(), e.get); err != nil || s.Adm.Mode != signer.PriorityRequest || s.Adm.Epoch.String() != "30s" || s.Adm.Rotation != 64 {
		t.Fatalf("explicit: err=%v adm=%+v", err, s.Adm)
	}
}

func TestAdmissionConfigFailsClosed(t *testing.T) {
	fx := testutil.Key(t)
	cases := map[string]struct {
		mut  func(envMap)
		want string
	}{
		"priority without key": {func(e envMap) { e["SIGNER_ADMISSION"] = "priority" }, "needs PRIORITY_KEY_FILE"},
		"priority key for other kid": {func(e envMap) {
			e["SIGNER_ADMISSION"], e["PRIORITY_KEY_FILE"] = "priority", writePriorityKey(t, "other")
		}, "does not match"},
		"priority key missing": {func(e envMap) {
			e["SIGNER_ADMISSION"], e["PRIORITY_KEY_FILE"] = "priority", "/nonexistent/priority.key"
		}, "no such file"},
		"key file in n48 mode": {func(e envMap) { e["PRIORITY_KEY_FILE"] = writePriorityKey(t, fx.Meta.KID) }, "SIGNER_ADMISSION is not priority"},
		"unknown mode":         {func(e envMap) { e["SIGNER_ADMISSION"] = "dagor" }, "must be n48 or priority"},
		"bad max deadline":     {func(e envMap) { e["SIGNER_MAX_DEADLINE"] = "-1s" }, "SIGNER_MAX_DEADLINE"},
		"bad controller": {func(e envMap) {
			e["SIGNER_ADMISSION"], e["PRIORITY_KEY_FILE"], e["SIGNER_PRIORITY_CONTROLLER"] = "priority", writePriorityKey(t, fx.Meta.KID), "v3"
		}, "SIGNER_PRIORITY_CONTROLLER"},
		"queue sample too short":          {func(e envMap) { e["SIGNER_QUEUE_SAMPLE"] = "1ms" }, "SIGNER_QUEUE_SAMPLE"},
		"priority mode without admission": {func(e envMap) { e["SIGNER_PRIORITY"] = "stable" }, "SIGNER_ADMISSION is not priority"},
		"bad priority mode": {func(e envMap) {
			e["SIGNER_ADMISSION"], e["PRIORITY_KEY_FILE"], e["SIGNER_PRIORITY"] = "priority", writePriorityKey(t, fx.Meta.KID), "session"
		}, "must be stable or request"},
		"epoch too short": {func(e envMap) {
			e["SIGNER_ADMISSION"], e["PRIORITY_KEY_FILE"], e["SIGNER_PRIORITY_EPOCH"] = "priority", writePriorityKey(t, fx.Meta.KID), "5s"
		}, "SIGNER_PRIORITY_EPOCH"},
		"rotation steps over the floor band": {func(e envMap) {
			e["SIGNER_ADMISSION"], e["PRIORITY_KEY_FILE"], e["SIGNER_PRIORITY_ROTATION"] = "priority", writePriorityKey(t, fx.Meta.KID), "8"
		}, "SIGNER_PRIORITY_ROTATION"},
		"rotation not a power of two": {func(e envMap) {
			e["SIGNER_ADMISSION"], e["PRIORITY_KEY_FILE"], e["SIGNER_PRIORITY_ROTATION"] = "priority", writePriorityKey(t, fx.Meta.KID), "6"
		}, "SIGNER_PRIORITY_ROTATION"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := baseEnv(t, fx, 1)
			tc.mut(e)
			mustFail(t, e, tc.want)
		})
	}
}

// TestWrongShareIndexRejected (T9): signer 1 given share-2.json refuses to start.
func TestWrongShareIndexRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := baseEnv(t, fx, 1)
	e["SHARE_FILE"] = fx.SharePath(2)
	mustFail(t, e, "share is for signer 2, this is signer 1")

	// Relabelling share 2 as index 1 does not help: it fails v^si == vk_1.
	e["SHARE_FILE"] = rewriteShare(t, fx.SharePath(2), func(f *keyshare.File) { f.SignerIndex = 1 })
	mustFail(t, e, "does not match its verification key")
}

// TestWrongKidRejected (T9): a share whose kid differs from public-meta.json.
func TestWrongKidRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := baseEnv(t, fx, 3)
	e["SHARE_FILE"] = rewriteShare(t, fx.SharePath(3), func(f *keyshare.File) { f.KID = "AAAAAAAAAAAAAAAAAAAAAA" })
	mustFail(t, e, "does not match meta kid")
}

func TestCorruptedShareRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := baseEnv(t, fx, 3)
	e["SHARE_FILE"] = rewriteShare(t, fx.SharePath(3), func(f *keyshare.File) {
		b, _ := base64.StdEncoding.DecodeString(f.Si)
		b[len(b)/2] ^= 1
		f.Si = base64.StdEncoding.EncodeToString(b)
	})
	mustFail(t, e, "does not match its verification key")
}

func TestMultiShareFileRejected(t *testing.T) {
	fx := testutil.Key(t)
	e := baseEnv(t, fx, 1)
	a, _ := os.ReadFile(fx.SharePath(1))
	b, _ := os.ReadFile(fx.SharePath(2))
	p := filepath.Join(t.TempDir(), "all.json")
	_ = os.WriteFile(p, append(a, b...), 0o600)
	e["SHARE_FILE"] = p
	mustFail(t, e, "exactly one share")
}

// TestSignerFailsClosed (I9): every missing or bad input aborts startup.
func TestSignerFailsClosed(t *testing.T) {
	fx := testutil.Key(t)
	for _, name := range []string{"SIGNER_ID", "META_FILE", "POLICY_FILE", "AUDIT_LOG", "TLS_CERT", "TLS_KEY", "TLS_CA"} {
		t.Run("missing "+name, func(t *testing.T) {
			e := baseEnv(t, fx, 1)
			delete(e, name)
			mustFail(t, e, name+" is not set")
		})
	}
	cases := map[string]struct {
		mut  func(envMap)
		want string
	}{
		"no share source":     {func(e envMap) { delete(e, "SHARE_FILE") }, "no share source"},
		"missing share file":  {func(e envMap) { e["SHARE_FILE"] = "/nonexistent/share-1.json" }, "no such file"},
		"both share sources":  {func(e envMap) { e["VAULT_ADDR"] = "http://127.0.0.1:1" }, "configure exactly one"},
		"vault without token": {func(e envMap) { delete(e, "SHARE_FILE"); e["VAULT_ADDR"] = "https://127.0.0.1:1" }, "VAULT_TOKEN is not set"},
		"vault unreachable": {func(e envMap) {
			delete(e, "SHARE_FILE")
			e["VAULT_ADDR"] = "https://127.0.0.1:1"
			e["VAULT_TOKEN"] = "t"
		}, "vault request"},
		// Audit E-1: https only; plain http only with the explicit dev flag.
		"vault plain http": {func(e envMap) {
			delete(e, "SHARE_FILE")
			e["VAULT_ADDR"] = "http://127.0.0.1:1"
			e["VAULT_TOKEN"] = "t"
		}, "uses plain http"},
		"vault other scheme": {func(e envMap) {
			delete(e, "SHARE_FILE")
			e["VAULT_ADDR"] = "ftp://127.0.0.1:1"
			e["VAULT_TOKEN"] = "t"
		}, "must use https"},
		"vault dev flag typo": {func(e envMap) {
			delete(e, "SHARE_FILE")
			e["VAULT_ADDR"] = "http://127.0.0.1:1"
			e["VAULT_TOKEN"] = "t"
			e["VAULT_DEV_ALLOW_HTTP"] = "true"
		}, "only \"1\" is accepted"},
		"vault http with dev flag": {func(e envMap) { // passes the scheme check, then fails to connect
			delete(e, "SHARE_FILE")
			e["VAULT_ADDR"] = "http://127.0.0.1:1"
			e["VAULT_TOKEN"] = "t"
			e["VAULT_DEV_ALLOW_HTTP"] = "1"
		}, "vault request"},
		"signer id 0":            {func(e envMap) { e["SIGNER_ID"] = "0" }, "outside [1,5]"},
		"signer id 6":            {func(e envMap) { e["SIGNER_ID"] = "6" }, "outside [1,5]"},
		"signer id not a number": {func(e envMap) { e["SIGNER_ID"] = "one" }, "not an integer"},
		"missing meta":           {func(e envMap) { e["META_FILE"] = "/nonexistent/public-meta.json" }, "no such file"},
		"corrupt meta":           {func(e envMap) { e["META_FILE"] = writeTemp(t, `{"version":1`) }, "decode"},
		"meta with extra field":  {func(e envMap) { e["META_FILE"] = metaWithExtra(t, fx.MetaPath) }, "unknown field"},
		"corrupt policy":         {func(e envMap) { e["POLICY_FILE"] = writeTemp(t, `{}`) }, "issuer is required"},
		"missing policy file":    {func(e envMap) { e["POLICY_FILE"] = "/nonexistent/policy.json" }, "no such file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := baseEnv(t, fx, 1)
			tc.mut(e)
			mustFail(t, e, tc.want)
		})
	}
}

func writeTemp(t *testing.T, s string) string {
	p := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func metaWithExtra(t *testing.T, src string) string {
	b, _ := os.ReadFile(src)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["private_key"] = "x"
	out, _ := json.Marshal(m)
	return writeTemp(t, string(out))
}

// TestShareFileMustNameExactlyOneFile (audit C-2, I4): SHARE_FILE names one
// regular file holding this signer's share. A list, a directory or a glob
// fails closed, and a successful load yields exactly one share, whose index
// is SIGNER_ID. Mutation M10b (a loader that accepts several share files)
// must fail this test.
func TestShareFileMustNameExactlyOneFile(t *testing.T) {
	fx := testutil.Key(t)
	for name, v := range map[string]string{
		"comma list":   fx.SharePath(1) + "," + fx.SharePath(2),
		"comma list 3": fx.SharePath(1) + "," + fx.SharePath(2) + "," + fx.SharePath(3),
		"directory":    fx.Dir,
		"glob":         filepath.Join(fx.Dir, "share-*.json"),
	} {
		t.Run(name, func(t *testing.T) {
			e := baseEnv(t, fx, 1)
			e["SHARE_FILE"] = v
			if s, err := load(context.Background(), e.get); err == nil {
				t.Fatalf("SHARE_FILE=%q loaded (share %d); want refusal", v, s.Share.Id)
			}
		})
	}
	s, err := load(context.Background(), baseEnv(t, fx, 3).get)
	if err != nil {
		t.Fatal(err)
	}
	if s.Share == nil || int(s.Share.Id) != 3 {
		t.Fatalf("loaded share %+v, want index 3", s.Share)
	}
	// Structural: settings can hold one share and nothing else share-typed.
	n := 0
	st := reflect.TypeOf(settings{})
	shareT := reflect.TypeOf((*tcrsa.KeyShare)(nil))
	for i := 0; i < st.NumField(); i++ {
		ft := st.Field(i).Type
		if ft == shareT {
			n++
		} else if (ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array || ft.Kind() == reflect.Map) && ft.Elem() == shareT {
			t.Fatalf("settings.%s can hold several shares", st.Field(i).Name)
		}
	}
	if n != 1 {
		t.Fatalf("settings has %d share fields, want exactly 1", n)
	}
}
