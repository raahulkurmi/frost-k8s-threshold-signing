package froststate

import (
	"fmt"
	"sync"

	"github.com/bytemare/frost"
)

var Config *frost.Configuration

// Mu kept for DKG handlers only
var Mu sync.Mutex

// Signer — single instance for backward compat
var Signer *frost.Signer

// PoolSize — max concurrent signing requests
const PoolSize = 20

type SignerPool struct {
	ch chan *frost.Signer
}

var Pool *SignerPool

func (p *SignerPool) Get() *frost.Signer {
	return <-p.ch
}

func (p *SignerPool) Put(s *frost.Signer) {
	select {
	case p.ch <- s:
	default:
		fmt.Println("[pool] pool full, discarding")
	}
}
