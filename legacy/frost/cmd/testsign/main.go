//go:build legacy

package main

import (
	"frost-k8s-threshold-signing/legacy/frost/internal/coordinator"
	"frost-k8s-threshold-signing/legacy/frost/internal/signer"
)

func main() {

	s1 := signer.New("signer-1")
	s2 := signer.New("signer-2")
	s3 := signer.New("signer-3")

	signers := []*signer.Signer{
		s1,
		s2,
		s3,
	}

	c := coordinator.New(
		signers,
		2,
	)

	c.Sign("hello-frost")
}