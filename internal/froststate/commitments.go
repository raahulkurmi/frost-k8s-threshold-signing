package froststate

import "github.com/bytemare/frost"

var Commitments = make(
	map[uint64]*frost.Commitment,
)