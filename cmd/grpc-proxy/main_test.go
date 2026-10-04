package main

import (
	"path/filepath"
	"strings"
	"testing"

	"frost-k8s-threshold-signing/internal/testutil"
)

type envMap map[string]string

func (e envMap) get(k string) string { return e[k] }

func baseEnv(t *testing.T) envMap {
	t.Helper()
	fx := testutil.Key(t)
	pki := testutil.NewPKI(t)
	cc := pki.CoordinatorN(t, 2)
	return envMap{
		"META_FILE":        fx.MetaPath,
		"POLICY_FILE":      testutil.PolicyFile(t, t.TempDir(), testutil.PolicyConfig()),
		"SIGNER_ENDPOINTS": "1=https://signer-1:8443,2=https://signer-2:8443,3=https://signer-3:8443",
		"COORDINATOR_ID":   "2",
		"TLS_CERT":         cc.Cert,
		"TLS_KEY":          cc.Key,
		"TLS_CA":           pki.CA,
		"SOCKET_PATH":      filepath.Join(t.TempDir(), "s.sock"),
	}
}

// TestQuorumAbortDefaultsOff (audit C-1): the binary's own default for
// QUORUM_ABORT is off (N82). TestQuorumAbortOffByDefault checks only the
// library's zero Config, and every compose file sets QUORUM_ABORT explicitly,
// so this is the only test of the decision applied in N82.
func TestQuorumAbortDefaultsOff(t *testing.T) {
	e := baseEnv(t)
	for _, tc := range []struct {
		val     string
		set     bool
		want    bool
		wantErr string
	}{
		{set: false, want: false},
		{val: "", set: true, want: false},
		{val: "off", set: true, want: false},
		{val: "on", set: true, want: true},
		{val: "yes", set: true, wantErr: "QUORUM_ABORT"},
		{val: "ON", set: true, wantErr: "QUORUM_ABORT"},
	} {
		env := envMap{}
		for k, v := range e {
			env[k] = v
		}
		if tc.set {
			env["QUORUM_ABORT"] = tc.val
		}
		s, err := load(env.get)
		name := "unset"
		if tc.set {
			name = "QUORUM_ABORT=" + tc.val
		}
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%s: err = %v, want error containing %q", name, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.Abort != tc.want {
			t.Fatalf("%s: Abort = %v, want %v", name, s.Abort, tc.want)
		}
	}
}

// TestLoadDefaults (audit C-1): the other final defaults (README "Defaults",
// N82) as the binary applies them when nothing is set.
func TestLoadDefaults(t *testing.T) {
	s, err := load(baseEnv(t).get)
	if err != nil {
		t.Fatal(err)
	}
	if s.Strategy != "optimistic" || s.Fanout != "all" || s.Deadline.String() != "2s" || s.Abort || s.CoordID != 2 || len(s.Endpoints) != 3 {
		t.Fatalf("defaults: strategy=%s fanout=%s deadline=%s abort=%v coord=%d endpoints=%d",
			s.Strategy, s.Fanout, s.Deadline, s.Abort, s.CoordID, len(s.Endpoints))
	}
}
