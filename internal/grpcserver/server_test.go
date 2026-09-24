package grpcserver_test

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	externaljwtv1 "k8s.io/externaljwt/apis/v1"

	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/grpcserver"
	"frost-k8s-threshold-signing/internal/testutil"
	"frost-k8s-threshold-signing/internal/tlsconf"
)

// serve starts the ExternalJWTSigner on a Unix socket, as kube-apiserver
// dials it, and returns a v1 client.
func serve(t *testing.T, c *testutil.Cluster, co *coordinator.Coordinator) externaljwtv1.ExternalJWTSignerClient {
	t.Helper()
	srv, err := grpcserver.New(co, c.Fx.Meta, 3600, 3600)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "gs") // short path: sun_path is ~104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "signer.sock")
	lis, err := grpcserver.ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	g := grpcserver.NewGRPC(srv)
	go g.Serve(lis)
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return externaljwtv1.NewExternalJWTSignerClient(conn)
}

// TestFetchKeysPKIXRoundTrip (R-a): key taken only from FetchKeys, parsed
// with x509.ParsePKIXPublicKey, verifies a Sign()ed token with go-jose v2.
func TestFetchKeysPKIXRoundTrip(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	client := serve(t, c, c.NewCoordinator(t, coordinator.Strict, 5*time.Second, nil))
	ctx := context.Background()

	keys, err := client.FetchKeys(ctx, &externaljwtv1.FetchKeysRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 || keys.RefreshHintSeconds <= 0 || keys.DataTimestamp == nil || keys.DataTimestamp.AsTime().IsZero() {
		t.Fatalf("FetchKeys = %+v", keys)
	}
	k := keys.Keys[0]
	if k.KeyId != c.Fx.Meta.KID || k.ExcludeFromOidcDiscovery || len(k.KeyId) > 1024 {
		t.Fatalf("key %+v", k)
	}
	parsed, err := x509.ParsePKIXPublicKey(k.Key)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() != 2048 {
		t.Fatalf("FetchKeys key %T", parsed)
	}
	if again, _ := x509.MarshalPKIXPublicKey(pub); string(again) != string(k.Key) {
		t.Fatal("PKIX re-marshal differs")
	}

	claims := testutil.Payload(t, testutil.SAClaims("default", "default", time.Now(), time.Hour))
	resp, err := client.Sign(ctx, &externaljwtv1.SignJWTRequest{Claims: claims})
	if err != nil {
		t.Fatal(err)
	}
	std, err := testutil.VerifyRS256(resp.Header+"."+claims+"."+resp.Signature, pub)
	if err != nil {
		t.Fatal(err)
	}
	if std.Subject != "system:serviceaccount:default:default" {
		t.Fatalf("sub %q", std.Subject)
	}

	md, err := client.Metadata(ctx, &externaljwtv1.MetadataRequest{})
	if err != nil || md.MaxTokenExpirationSeconds != 3600 {
		t.Fatalf("Metadata = %v, %v", md, err)
	}

	// FetchKeys output is deterministic (identical across replicas and calls).
	keys2, _ := client.FetchKeys(ctx, &externaljwtv1.FetchKeysRequest{})
	if !keys2.DataTimestamp.AsTime().Equal(keys.DataTimestamp.AsTime()) || string(keys2.Keys[0].Key) != string(k.Key) {
		t.Fatal("FetchKeys not deterministic")
	}
	t.Logf("FetchKeys kid=%s (%d-byte PKIX), data_timestamp=%s, refresh=%ds; Sign() token verified by go-jose v2 with that key only",
		k.KeyId, len(k.Key), keys.DataTimestamp.AsTime().Format(time.RFC3339), keys.RefreshHintSeconds)
}

// TestSignErrorIsGeneric (N33): the error the token requester sees names no
// signer, no policy rule and no claim value; the coordinator log has them.
func TestSignErrorIsGeneric(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	var logs testutil.LogBuffer
	client := serve(t, c, c.NewCoordinator(t, coordinator.Strict, 5*time.Second, logs.Logger()))
	m := testutil.SAClaims("default", "default", time.Now(), time.Hour)
	m["aud"] = []string{"not-allowlisted"}
	resp, err := client.Sign(context.Background(), &externaljwtv1.SignJWTRequest{Claims: testutil.Payload(t, m)})
	if err == nil || resp != nil {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable || st.Message() != grpcserver.ErrMsgThreshold {
		t.Fatalf("caller got %v %q, want Unavailable %q", st.Code(), st.Message(), grpcserver.ErrMsgThreshold)
	}
	for _, leak := range []string{"signer", "policy", "aud", "not-allowlisted", "403", "refused", "valid shares"} {
		if strings.Contains(st.Message(), leak) {
			t.Fatalf("caller-visible error %q leaks %q", st.Message(), leak)
		}
	}
	l := logs.String()
	if !strings.Contains(l, `aud: audience \"not-allowlisted\" is not allowed`) || !strings.Contains(l, `"msg":"sign failed"`) {
		t.Fatalf("coordinator log lacks the specific reason:\n%s", l)
	}
	// Malformed claims: generic InvalidArgument.
	_, err = client.Sign(context.Background(), &externaljwtv1.SignJWTRequest{Claims: "not base64!"})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument || st.Message() != grpcserver.ErrMsgInvalidRequest {
		t.Fatalf("malformed claims: %v", err)
	}
	t.Logf("caller sees: %s / %q; coordinator log keeps the policy reason", st.Code(), st.Message())
}

// TestTCPListenerRequiresLBClientCert: a coordinator's TCP gRPC listener
// accepts only a client cert with SAN exactly "lb" from the deployment CA.
func TestTCPListenerRequiresLBClientCert(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{})
	srv, err := grpcserver.New(c.NewCoordinator(t, coordinator.Strict, 5*time.Second, nil), c.Fx.Meta, 3600, 3600)
	if err != nil {
		t.Fatal(err)
	}
	gc := c.PKI.CoordinatorGRPC(t)
	tc, err := tlsconf.CoordinatorGRPCServer(gc.Cert, gc.Key, c.PKI.CA)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpcserver.NewGRPC(srv, grpc.Creds(credentials.NewTLS(tc)))
	go g.Serve(lis)
	t.Cleanup(g.Stop)

	dial := func(cert *testutil.CertPaths, caPath string) error {
		pool := x509.NewCertPool()
		pem, _ := os.ReadFile(caPath)
		pool.AppendCertsFromPEM(pem)
		cfg := &tls.Config{RootCAs: pool, ServerName: tlsconf.CoordinatorGRPCName, MinVersion: tls.VersionTLS13}
		if cert != nil {
			kp, err := tls.LoadX509KeyPair(cert.Cert, cert.Key)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Certificates = []tls.Certificate{kp}
		}
		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if err != nil {
			return err
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err = externaljwtv1.NewExternalJWTSignerClient(conn).FetchKeys(ctx, &externaljwtv1.FetchKeysRequest{})
		return err
	}
	lb := c.PKI.LB(t)
	if err := dial(&lb, c.PKI.CA); err != nil {
		t.Fatalf("lb client rejected: %v", err)
	}
	other := testutil.NewPKI(t)
	foreignLB := other.LB(t)
	coord := c.CoordinatorCert()
	signer1 := c.PKI.Signer(t, 1)
	attacker := c.PKI.Issue(t, "attacker", []string{"attacker"}, x509.ExtKeyUsageClientAuth)
	for name, cert := range map[string]*testutil.CertPaths{
		"no client cert":                   nil,
		"coordinator cert (signer-facing)": &coord,
		"signer-1 cert":                    &signer1,
		"SAN attacker, same CA":            &attacker,
		"SAN lb, foreign CA":               &foreignLB,
	} {
		err := dial(cert, c.PKI.CA)
		if err == nil {
			t.Fatalf("%s: FetchKeys succeeded", name)
		}
		t.Logf("%s: rejected (%v)", name, status.Code(err))
	}
}

func TestSignBelowThresholdReturnsErrorNoToken(t *testing.T) {
	c := testutil.StartCluster(t, testutil.ClusterOpts{Wrap: func(id int, h http.Handler) http.Handler {
		if id >= 3 {
			return testutil.Down()
		}
		return h
	}})
	client := serve(t, c, c.NewCoordinator(t, coordinator.Strict, 5*time.Second, nil))
	claims := testutil.Payload(t, testutil.SAClaims("default", "default", time.Now(), time.Hour))
	resp, err := client.Sign(context.Background(), &externaljwtv1.SignJWTRequest{Claims: claims})
	if err == nil || resp != nil {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code %v", status.Code(err))
	}
	t.Logf("Sign error: %v", err)

	if _, err := client.Sign(context.Background(), &externaljwtv1.SignJWTRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty claims: %v", err)
	}
}

func TestNewValidates(t *testing.T) {
	fx := testutil.Key(t)
	var s grpcserver.Signer = (*coordinator.Coordinator)(nil)
	if _, err := grpcserver.New(s, fx.Meta, 599, 3600); err == nil {
		t.Error("max_token_expiration_seconds 599 accepted")
	}
	if _, err := grpcserver.New(s, fx.Meta, 3600, 0); err == nil {
		t.Error("refresh hint 0 accepted")
	}
	if _, err := grpcserver.New(nil, fx.Meta, 3600, 3600); err == nil {
		t.Error("nil signer accepted")
	}
}

func TestListenUnixRefusesNonSocket(t *testing.T) {
	dir, _ := os.MkdirTemp("", "gs")
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "file")
	_ = os.WriteFile(p, []byte("x"), 0o600)
	if _, err := grpcserver.ListenUnix(p); err == nil {
		t.Fatal("replaced a regular file")
	}
	// A stale socket is replaced.
	s := filepath.Join(dir, "s.sock")
	l, _ := net.Listen("unix", s)
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	l2, err := grpcserver.ListenUnix(s)
	if err != nil {
		t.Fatal(err)
	}
	l2.Close()
}
