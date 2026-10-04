package test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTopologyGuard (audit E-2): deploy/multihost/deploy.sh refuses any share
// placement where one host holds t or more shares (it could sign alone), a
// signer listed twice or not at all, or a share on the coordinator host. The
// guard is the sourced function deploy.sh calls before the key ceremony.
func TestTopologyGuard(t *testing.T) {
	cases := []struct {
		name, coord, t, signers, refuse string // refuse: "" = accepted, else a substring of the reason
	}{
		{"Level 1 (2+2+1)", "tk8s", "3", "1:sig-a:8441 2:sig-a:8442 3:sig-b:8443 4:sig-b:8444 5:sig-c:8445", ""},
		{"Level 2 (one per host)", "coord", "3", "1:s1:8441 2:s2:8441 3:s3:8441 4:s4:8441 5:s5:8441", ""},
		{"3 shares on one host", "tk8s", "3", "1:sig-a:8441 2:sig-a:8442 3:sig-a:8443 4:sig-b:8444 5:sig-c:8445", "host sig-a would hold 3 shares"},
		{"all on one host", "tk8s", "3", "1:h:1 2:h:2 3:h:3 4:h:4 5:h:5", "would hold 5 shares"},
		{"t=2 forbids pairs", "tk8s", "2", "1:sig-a:8441 2:sig-a:8442 3:sig-b:8443 4:sig-c:8444 5:sig-d:8445", "at most t-1 = 1"},
		{"share on coordinator", "sig-c", "3", "1:sig-a:8441 2:sig-a:8442 3:sig-b:8443 4:sig-b:8444 5:sig-c:8445", "coordinator host"},
		{"signer listed twice", "tk8s", "3", "1:a:1 1:b:1 2:c:1 3:d:1 4:e:1 5:f:1", "signer 1 must be listed exactly once (found 2)"},
		{"signer missing", "tk8s", "3", "1:a:1 2:b:1 3:c:1 4:d:1", "signer 5 must be listed exactly once (found 0)"},
		{"bad threshold", "tk8s", "x", "1:a:1 2:b:1 3:c:1 4:d:1 5:e:1", "not an integer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `source deploy/multihost/topology-guard.sh && topology_guard "$1" "$2" "$3"`, "guard", tc.coord, tc.t, tc.signers)
			cmd.Dir = ".."
			out, err := cmd.CombinedOutput()
			switch {
			case tc.refuse == "" && err != nil:
				t.Fatalf("refused a safe topology: %v: %s", err, out)
			case tc.refuse != "" && err == nil:
				t.Fatalf("accepted an unsafe topology (want refusal containing %q)", tc.refuse)
			case tc.refuse != "" && !strings.Contains(string(out), tc.refuse):
				t.Fatalf("refusal %q does not contain %q", out, tc.refuse)
			}
		})
	}
}
