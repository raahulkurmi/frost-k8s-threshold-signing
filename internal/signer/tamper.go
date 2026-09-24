//go:build !testmalicious

package signer

import "github.com/niclabs/tcrsa"

// tamper is the identity in every normal build. The testmalicious build tag
// swaps in tamper_testmalicious.go, which corrupts shares for tests (T5).
func tamper(_ int, ss *tcrsa.SigShare) *tcrsa.SigShare { return ss }
