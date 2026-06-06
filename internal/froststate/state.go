package froststate

import (
	"sync"

	"github.com/bytemare/frost"
)

var Signer *frost.Signer
var Config *frost.Configuration

// Mu protects concurrent access to Signer state during signing sessions.
// FROST signing is stateful — concurrent requests cause race conditions.
var Mu sync.Mutex
