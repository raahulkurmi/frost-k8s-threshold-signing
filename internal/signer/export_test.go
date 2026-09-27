package signer

import "time"

// SetTestHookBeforeRSA exposes the pre-RSA hook to this package's external
// tests only (export_test.go is compiled only into the test binary).
func SetTestHookBeforeRSA(f func()) { testHookBeforeRSA = f }

// SetRSAEstimate overrides the EWMA RSA-time estimate (tests only).
func (s *Server) SetRSAEstimate(d time.Duration) { s.rsaEWMA.Store(int64(d)) }

// AdmittedFraction returns the priority stage's admitted fraction f (tests only).
func (s *Server) AdmittedFraction() float64 { return s.prio.fraction() }

// SetAdmittedFraction forces f (tests only; use a long Admission.Window so it holds).
func (s *Server) SetAdmittedFraction(f float64) { s.prio.setFraction(f) }

// NewAdmissionForTest exposes the priority stage alone (tests only).
func NewAdmissionForTest(key []byte, cfg AdmissionConfig) *AdmissionForTest {
	return &AdmissionForTest{a: newAdmission(1, key, cfg, nil)}
}

// AdmissionForTest drives the priority stage with an explicit clock.
type AdmissionForTest struct{ a *admission }

// Decide returns whether a request with priority p from client is admitted and why not.
func (t *AdmissionForTest) Decide(now time.Time, p uint16, client string, budget time.Duration) (bool, string) {
	d := t.a.decide(now, p, client, budget)
	return d.ok, d.kind
}

// ObserveShed / ObserveWait feed the overload signal.
func (t *AdmissionForTest) ObserveShed()                { t.a.observeShed() }
func (t *AdmissionForTest) ObserveWait(d time.Duration) { t.a.observeWait(d) }
func (t *AdmissionForTest) Fraction() float64           { return t.a.fraction() }
func (t *AdmissionForTest) SetFraction(f float64)       { t.a.setFraction(f) }
