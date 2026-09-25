package signer

// SetTestHookBeforeRSA exposes the pre-RSA hook to this package's external
// tests only (export_test.go is compiled only into the test binary).
func SetTestHookBeforeRSA(f func()) { testHookBeforeRSA = f }
