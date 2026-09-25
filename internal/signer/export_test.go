package signer

import "time"

// SetTestHookBeforeRSA exposes the pre-RSA hook to this package's external
// tests only (export_test.go is compiled only into the test binary).
func SetTestHookBeforeRSA(f func()) { testHookBeforeRSA = f }

// SetRSAEstimate overrides the EWMA RSA-time estimate (tests only).
func (s *Server) SetRSAEstimate(d time.Duration) { s.rsaEWMA.Store(int64(d)) }
