package coordinator_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/testutil"
)

// TestResponseSANCheckWithoutTLSPinning (audit C-3, mutation M5a): the
// coordinator checks the responder's certificate SAN against the endpoint id
// itself, not only through the TLS client configuration. Here endpoint 3 uses a
// client that trusts the CA but does not pin signer-3 (it expects signer-4) and
// points at signer 4's server. TLS succeeds; the coordinator must still refuse
// the response as not coming from signer-3, before any share verification.
func TestResponseSANCheckWithoutTLSPinning(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	eps := c.Endpoints(t, 1, 2, 4, 5)
	cert, err := tls.LoadX509KeyPair(c.CoordinatorCert().Cert, c.CoordinatorCert().Key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(c.PKI.CA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad CA")
	}
	unpinned := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "signer-4"}
	eps = append(eps, coordinator.Endpoint{ID: 3, URL: c.Servers[4].URL,
		Client: &http.Client{Transport: &http.Transport{TLSClientConfig: unpinned, ForceAttemptHTTP2: true}}})
	co, err := coordinator.New(coordinator.Config{Meta: c.Fx.Meta, Endpoints: eps, Deadline: 5 * time.Second, Strategy: coordinator.Strict})
	if err != nil {
		t.Fatal(err)
	}
	res, err := co.Sign(context.Background(), claims(t))
	if err != nil {
		t.Fatal(err) // signers 1, 2, 4, 5 are honest: the token still forms
	}
	for _, id := range res.Signers {
		if id == 3 {
			t.Fatalf("combined a share attributed to signer 3: %v", res.Signers)
		}
	}
	found := false
	for _, f := range res.Excluded {
		if f.SignerID == 3 {
			found = true
			if !strings.Contains(f.Reason, "is not signer-3") {
				t.Fatalf("endpoint 3 excluded for %q; want the response-side identity check (\"is not signer-3\")", f.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("endpoint 3 (answered by signer-4) not excluded: %+v", res.Excluded)
	}
}
