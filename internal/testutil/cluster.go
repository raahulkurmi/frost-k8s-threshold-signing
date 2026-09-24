package testutil

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"frost-k8s-threshold-signing/internal/audit"
	"frost-k8s-threshold-signing/internal/coordinator"
	"frost-k8s-threshold-signing/internal/policy"
	"frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/tlsconf"
	"frost-k8s-threshold-signing/internal/wire"
)

// ClusterOpts customises StartCluster.
type ClusterOpts struct {
	// Wrap, if set, wraps signer id's HTTP handler (fault injection).
	Wrap func(id int, h http.Handler) http.Handler
	// Policy overrides the signers' policy.
	Policy *policy.Config
}

// Cluster is n real signers served over mTLS on loopback, plus a PKI and key.
type Cluster struct {
	Fx      *Fixture
	PKI     *PKI
	Servers map[int]*httptest.Server
	coord   CertPaths
}

// StartCluster starts all Parties signers in-process.
func StartCluster(t testing.TB, opts ClusterOpts) *Cluster {
	t.Helper()
	fx := Key(t)
	pki := NewPKI(t)
	pc := PolicyConfig()
	if opts.Policy != nil {
		pc = *opts.Policy
	}
	pol, err := policy.New(pc)
	if err != nil {
		t.Fatal(err)
	}
	c := &Cluster{Fx: fx, PKI: pki, Servers: map[int]*httptest.Server{}, coord: pki.Coordinator(t)}
	for id := 1; id <= Parties; id++ {
		al, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { al.Close() })
		srv, err := signer.New(signer.Config{ID: id, Meta: fx.Meta, Share: fx.Shares[id-1], Policy: pol, Audit: al,
			Logger: slog.New(slog.NewTextHandler(discard{}, nil))})
		if err != nil {
			t.Fatal(err)
		}
		sc := pki.Signer(t, id)
		tc, err := tlsconf.SignerServer(sc.Cert, sc.Key, pki.CA, id)
		if err != nil {
			t.Fatal(err)
		}
		var h http.Handler = srv.Handler()
		if opts.Wrap != nil {
			h = opts.Wrap(id, h)
		}
		ts := httptest.NewUnstartedServer(h)
		ts.TLS = tc
		ts.StartTLS()
		t.Cleanup(ts.Close)
		c.Servers[id] = ts
	}
	return c
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// Endpoints returns coordinator endpoints for the given signer IDs (all if none).
func (c *Cluster) Endpoints(t testing.TB, ids ...int) []coordinator.Endpoint {
	t.Helper()
	if len(ids) == 0 {
		for i := 1; i <= Parties; i++ {
			ids = append(ids, i)
		}
	}
	var eps []coordinator.Endpoint
	for _, id := range ids {
		tc, err := tlsconf.CoordinatorClient(c.coord.Cert, c.coord.Key, c.PKI.CA, id)
		if err != nil {
			t.Fatal(err)
		}
		eps = append(eps, coordinator.Endpoint{ID: id, URL: c.Servers[id].URL,
			Client: &http.Client{Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true}}})
	}
	return eps
}

// CoordinatorCert returns the coordinator's client cert paths.
func (c *Cluster) CoordinatorCert() CertPaths { return c.coord }

// LogBuffer is a concurrency-safe buffer for capturing slog JSON output.
type LogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *LogBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *LogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Logger returns a JSON slog logger writing to l.
func (l *LogBuffer) Logger() *slog.Logger { return slog.New(slog.NewJSONHandler(l, nil)) }

// NewCoordinator builds a coordinator over the given signer IDs.
func (c *Cluster) NewCoordinator(t testing.TB, strategy coordinator.Strategy, deadline time.Duration, log *slog.Logger, ids ...int) *coordinator.Coordinator {
	t.Helper()
	co, err := coordinator.New(coordinator.Config{Meta: c.Fx.Meta, Endpoints: c.Endpoints(t, ids...), Deadline: deadline, Strategy: strategy, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	return co
}

// CorruptShare wraps a signer handler so successful responses carry a
// corrupted (but well-formed) Xi.
func CorruptShare(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			copyResponse(w, rec)
			return
		}
		var resp wire.SignShareResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			copyResponse(w, rec)
			return
		}
		xi, _ := base64.StdEncoding.DecodeString(resp.Share.Xi)
		xi[len(xi)/2] ^= 0x5a
		resp.Share.Xi = base64.StdEncoding.EncodeToString(xi)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// Delay wraps a signer handler to sleep d before answering (or until the
// client goes away).
func Delay(d time.Duration, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Down makes a signer answer 503 to everything (a stopped signer).
func Down() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "signer down", http.StatusServiceUnavailable)
	})
}

func copyResponse(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}
