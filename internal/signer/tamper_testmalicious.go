//go:build testmalicious

package signer

import (
	"sync"

	"github.com/niclabs/tcrsa"
)

// TEST ONLY. Compiled only with -tags testmalicious (never in images or
// runtime binaries; TestCoordinatorHasNoSecretTypes checks the default
// build excludes this file). Signers whose ID is marked malicious return a
// well-formed but corrupted signature share.
var (
	maliciousMu  sync.RWMutex
	maliciousIDs = map[int]bool{}
)

// SetMalicious marks signer IDs as malicious (replacing any previous set).
func SetMalicious(ids ...int) {
	maliciousMu.Lock()
	defer maliciousMu.Unlock()
	maliciousIDs = map[int]bool{}
	for _, id := range ids {
		maliciousIDs[id] = true
	}
}

func tamper(id int, ss *tcrsa.SigShare) *tcrsa.SigShare {
	maliciousMu.RLock()
	bad := maliciousIDs[id]
	maliciousMu.RUnlock()
	if !bad {
		return ss
	}
	xi := append([]byte(nil), ss.Xi...)
	xi[len(xi)/2] ^= 0x5a
	return &tcrsa.SigShare{Id: ss.Id, Xi: xi, C: ss.C, Z: ss.Z}
}
