// Package coordinator collects threshold RSA signature shares from signers
// and combines them into an RS256 signature.
//
// It holds only public metadata (invariant I3): the group public key, the
// share verification keys, t and n. It must never import a secret-share
// type; TestCoordinatorHasNoSecretTypes enforces this.
package coordinator

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/niclabs/tcrsa"

	"frost-k8s-threshold-signing/internal/jwtfmt"
	"frost-k8s-threshold-signing/internal/keymeta"
	"frost-k8s-threshold-signing/internal/wire"
)

// Strategy selects how signature shares are verified (NOTES.md R-c).
type Strategy string

const (
	// Strict verifies every share (in parallel, as it arrives), joins t valid
	// shares, then verifies the final signature.
	Strict Strategy = "strict"
	// Optimistic joins the first t well-formed shares and verifies the final
	// signature; only on failure does it verify each share, exclude and
	// attribute the bad ones, and retry with the remaining valid shares.
	Optimistic Strategy = "optimistic"
)

// ParseStrategy accepts "strict" or "optimistic".
func ParseStrategy(s string) (Strategy, error) {
	switch Strategy(s) {
	case Strict, Optimistic:
		return Strategy(s), nil
	}
	return "", fmt.Errorf("unknown verify strategy %q (want strict or optimistic)", s)
}

// Endpoint is one signer. ID is its authenticated identity (signer-<ID>).
type Endpoint struct {
	ID     int
	URL    string       // e.g. https://signer-3:8443
	Client *http.Client // TLS config pinned to signer-<ID> (tlsconf.CoordinatorClient)
}

// Config wires a coordinator.
type Config struct {
	Meta      *keymeta.Meta
	Endpoints []Endpoint
	Deadline  time.Duration
	Strategy  Strategy
	Logger    *slog.Logger
}

// Coordinator is safe for concurrent use.
type Coordinator struct {
	meta      *keymeta.Meta
	endpoints []Endpoint
	deadline  time.Duration
	strategy  Strategy
	log       *slog.Logger
	headerSeg string
}

// New validates cfg. At least t endpoints with unique IDs in [1,n] are required.
func New(cfg Config) (*Coordinator, error) {
	if cfg.Meta == nil {
		return nil, errors.New("coordinator: meta is required")
	}
	if cfg.Deadline <= 0 {
		return nil, errors.New("coordinator: deadline must be > 0")
	}
	if _, err := ParseStrategy(string(cfg.Strategy)); err != nil {
		return nil, fmt.Errorf("coordinator: %w", err)
	}
	if len(cfg.Endpoints) < cfg.Meta.Threshold {
		return nil, fmt.Errorf("coordinator: %d signer endpoints configured, threshold is %d", len(cfg.Endpoints), cfg.Meta.Threshold)
	}
	seen := map[int]bool{}
	for _, ep := range cfg.Endpoints {
		if ep.ID < 1 || ep.ID > cfg.Meta.Parties {
			return nil, fmt.Errorf("coordinator: signer id %d outside [1,%d]", ep.ID, cfg.Meta.Parties)
		}
		if seen[ep.ID] {
			return nil, fmt.Errorf("coordinator: signer id %d configured twice", ep.ID)
		}
		seen[ep.ID] = true
		if ep.URL == "" || ep.Client == nil {
			return nil, fmt.Errorf("coordinator: signer %d needs a URL and a client", ep.ID)
		}
	}
	hdr, err := jwtfmt.EncodedHeader(cfg.Meta.KID)
	if err != nil {
		return nil, err
	}
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	return &Coordinator{meta: cfg.Meta, endpoints: cfg.Endpoints, deadline: cfg.Deadline, strategy: cfg.Strategy, log: lg, headerSeg: hdr}, nil
}

// SignerFailure attributes one signer's failure.
type SignerFailure struct {
	SignerID int    `json:"signer_id"`
	Reason   string `json:"reason"`
}

// ThresholdError is returned when fewer than t valid shares were obtained.
// No token is ever returned alongside it.
type ThresholdError struct {
	Valid    int
	Needed   int
	Failures []SignerFailure
}

func (e *ThresholdError) Error() string {
	var parts []string
	for _, f := range e.Failures {
		parts = append(parts, fmt.Sprintf("signer-%d: %s", f.SignerID, f.Reason))
	}
	return fmt.Sprintf("threshold not met: %d valid shares, need %d; failures: [%s]", e.Valid, e.Needed, strings.Join(parts, "; "))
}

// result is one signer's outcome.
type result struct {
	id       int
	share    *tcrsa.SigShare
	verified bool
	err      error
	fetch    time.Duration
	verify   time.Duration
}

// Result is a successful signing, with per-phase latencies.
type Result struct {
	Header    string // base64url header, as the proto requires
	Signature string // base64url signature, as the proto requires
	RequestID string
	Signers   []int // share IDs combined
	Excluded  []SignerFailure
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Sign produces base64url(header) and base64url(signature) for the proto's
// claims (already base64url, exactly the JWT's second segment; NOTES.md N8).
func (c *Coordinator) Sign(ctx context.Context, claims string) (*Result, error) {
	start := time.Now()
	if err := jwtfmt.CheckSegment(claims); err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}
	input := c.headerSeg + "." + claims
	if len(input) > jwtfmt.MaxSigningInput {
		return nil, fmt.Errorf("claims too large")
	}
	digest := sha256.Sum256([]byte(input))
	doc, err := tcrsa.PrepareDocumentHash(c.meta.PublicKey.Size(), crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	reqID := newRequestID()
	ctx, cancel := context.WithTimeout(ctx, c.deadline)
	defer cancel() // cancels outstanding signer requests once we return

	body, _ := json.Marshal(wire.SignShareRequest{SigningInput: input, RequestID: reqID})
	results := make(chan result, len(c.endpoints))
	for _, ep := range c.endpoints {
		go func(ep Endpoint) {
			r := c.fetch(ctx, ep, body, reqID)
			if r.err == nil && c.strategy == Strict {
				vs := time.Now()
				if err := r.share.Verify(doc, c.meta.Tcrsa); err != nil {
					r.err = fmt.Errorf("invalid signature share: %v", err)
				} else {
					r.verified = true
				}
				r.verify = time.Since(vs)
			}
			results <- r
		}(ep)
	}

	t := c.meta.Threshold
	valid := map[int]*tcrsa.SigShare{}      // verified shares, deduped by ID
	candidates := map[int]*tcrsa.SigShare{} // optimistic: well-formed, unverified
	var failures []SignerFailure
	fallback := c.strategy == Strict // optimistic switches to verifying after a failed join
	var maxVerify time.Duration
	var fanout, combine, finalVerify time.Duration
	var sig []byte
	var used []int

	fail := func(id int, reason string) {
		failures = append(failures, SignerFailure{SignerID: id, Reason: reason})
	}
	// verifyAll checks shares in parallel; bad ones are excluded and attributed.
	verifyAll := func(set map[int]*tcrsa.SigShare) {
		type vr struct {
			id  int
			err error
			d   time.Duration
		}
		ch := make(chan vr, len(set))
		for id, s := range set {
			go func(id int, s *tcrsa.SigShare) {
				vs := time.Now()
				err := s.Verify(doc, c.meta.Tcrsa)
				ch <- vr{id, err, time.Since(vs)}
			}(id, s)
		}
		for range set {
			v := <-ch
			maxVerify = max(maxVerify, v.d)
			if v.err != nil {
				fail(v.id, "invalid signature share: "+v.err.Error())
				c.log.Warn("excluded invalid signature share", "request_id", reqID, "signer_id", v.id, "err", v.err.Error())
			} else {
				valid[v.id] = set[v.id]
			}
		}
	}
	tryJoin := func(set map[int]*tcrsa.SigShare) ([]byte, []int, error) {
		ids := make([]int, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		ids = ids[:t]
		list := make(tcrsa.SigShareList, 0, t)
		for _, id := range ids {
			list = append(list, set[id])
		}
		js := time.Now()
		s, err := list.Join(doc, c.meta.Tcrsa)
		combine += time.Since(js)
		if err != nil {
			return nil, ids, err
		}
		vs := time.Now()
		err = rsa.VerifyPKCS1v15(c.meta.PublicKey, crypto.SHA256, digest[:], s)
		finalVerify += time.Since(vs)
		return s, ids, err
	}

	received := 0
collect:
	for received < len(c.endpoints) {
		select {
		case <-ctx.Done():
			// Deadline: count every signer that has not answered.
			for _, ep := range c.endpoints {
				if valid[ep.ID] == nil && candidates[ep.ID] == nil && !failed(failures, ep.ID) {
					fail(ep.ID, "no response before deadline")
				}
			}
			break collect
		case r := <-results:
			received++
			maxVerify = max(maxVerify, r.verify)
			if r.err != nil {
				fail(r.id, r.err.Error())
				if r.share != nil { // a returned-but-invalid share (strict)
					c.log.Warn("excluded invalid signature share", "request_id", reqID, "signer_id", r.id, "err", r.err.Error())
				}
				continue
			}
			if valid[r.id] != nil || candidates[r.id] != nil {
				fail(r.id, "duplicate share id") // unreachable with unique endpoints; defensive dedupe
				continue
			}
			switch {
			case r.verified:
				valid[r.id] = r.share
			case fallback:
				verifyAll(map[int]*tcrsa.SigShare{r.id: r.share})
			default:
				candidates[r.id] = r.share
			}

			if !fallback && len(candidates) >= t {
				fanout = time.Since(start)
				s, ids, err := tryJoin(candidates)
				if err == nil {
					sig, used = s, ids
					break collect
				}
				c.log.Warn("optimistic combine failed final verification; verifying shares individually", "request_id", reqID, "err", err.Error())
				fallback = true
				verifyAll(candidates)
				candidates = map[int]*tcrsa.SigShare{}
			}
			if len(valid) >= t {
				fanout = time.Since(start)
				s, ids, err := tryJoin(valid)
				if err != nil {
					// All joined shares individually verified; a bad combined
					// signature means the key metadata or library is broken.
					return nil, fmt.Errorf("combined signature from verified shares %v failed verification: %w", ids, err)
				}
				sig, used = s, ids
				break collect
			}
		}
	}
	cancel()

	if sig == nil {
		terr := &ThresholdError{Valid: len(valid), Needed: t, Failures: failures}
		c.log.Error("sign failed", "request_id", reqID, "strategy", c.strategy, "signers_contacted", len(c.endpoints),
			"valid_shares", len(valid), "failures", failures, "latency_ms", ms(time.Since(start)))
		return nil, terr
	}
	// Fail closed: the returned signature has passed rsa.VerifyPKCS1v15 in tryJoin.
	c.log.Info("signed", "request_id", reqID, "strategy", c.strategy, "signers_contacted", len(c.endpoints),
		"valid_shares", len(valid)+len(candidates), "combined", used, "excluded", failures,
		"latency_ms", ms(time.Since(start)), "fanout_ms", ms(fanout), "max_share_verify_ms", ms(maxVerify),
		"combine_ms", ms(combine), "final_verify_ms", ms(finalVerify))
	return &Result{
		Header:    c.headerSeg,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
		RequestID: reqID,
		Signers:   used,
		Excluded:  failures,
	}, nil
}

func failed(fs []SignerFailure, id int) bool {
	for _, f := range fs {
		if f.SignerID == id {
			return true
		}
	}
	return false
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// fetch asks one signer for its share and checks it is well-formed. The share
// ID is the endpoint's authenticated identity, never the response's claim.
func (c *Coordinator) fetch(ctx context.Context, ep Endpoint, body []byte, reqID string) result {
	st := time.Now()
	r := result{id: ep.ID}
	defer func() { r.fetch = time.Since(st) }()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(ep.URL, "/")+wire.SignSharePath, bytes.NewReader(body))
	if err != nil {
		r.err = err
		return r
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ep.Client.Do(req)
	if err != nil {
		r.err = fmt.Errorf("request failed: %v", unwrapURL(err))
		return r
	}
	defer resp.Body.Close()
	// R-b: the share's ID is bound to the mTLS identity of the responder.
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		r.err = errors.New("response not received over mTLS")
		return r
	}
	if leaf := resp.TLS.PeerCertificates[0]; len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != fmt.Sprintf("signer-%d", ep.ID) {
		r.err = fmt.Errorf("peer certificate %v is not signer-%d", leaf.DNSNames, ep.ID)
		return r
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, wire.MaxResponseBytes+1))
	if err != nil {
		r.err = fmt.Errorf("read response: %v", err)
		return r
	}
	if len(raw) > wire.MaxResponseBytes {
		r.err = errors.New("response too large")
		return r
	}
	if resp.StatusCode != http.StatusOK {
		var er wire.ErrorResponse
		if json.Unmarshal(raw, &er) == nil && er.Error != "" {
			r.err = fmt.Errorf("refused (HTTP %d %s): %s", resp.StatusCode, er.Error, er.Reason)
		} else {
			r.err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return r
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var sr wire.SignShareResponse
	if err := dec.Decode(&sr); err != nil {
		r.err = fmt.Errorf("malformed response: %v", err)
		return r
	}
	if sr.SignerID != ep.ID {
		r.err = fmt.Errorf("response claims signer_id %d but came from authenticated signer-%d", sr.SignerID, ep.ID)
		return r
	}
	if sr.RequestID != reqID {
		r.err = fmt.Errorf("response request_id %q does not match %q", sr.RequestID, reqID)
		return r
	}
	share, err := sr.Share.ToTcrsa(ep.ID, c.meta.Parties, c.meta.PublicKey.N)
	if err != nil {
		r.err = fmt.Errorf("malformed share: %v", err)
		// keep r.share nil: nothing usable
		return r
	}
	r.share = share
	return r
}

func unwrapURL(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		if inner := ue.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}

// Meta returns the public key metadata.
func (c *Coordinator) Meta() *keymeta.Meta { return c.meta }

// Strategy returns the configured verification strategy.
func (c *Coordinator) Strategy() Strategy { return c.strategy }
