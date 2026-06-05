package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"frost-k8s-threshold-signing/internal/types"
)

type Signer struct {
	ID         string
	PrivateKey *ecdsa.PrivateKey
}

func New(id string) *Signer {

	key, err := GenerateKeyPair()

	if err != nil {
		panic(err)
	}

	return &Signer{
		ID:         id,
		PrivateKey: key,
	}
}

func (s *Signer) Sign(message string) types.PartialSignature {

	fmt.Printf("[%s] signing message: %s\n", s.ID, message)

	hash := sha256.Sum256([]byte(message))

	signature, err := ecdsa.SignASN1(
		rand.Reader,
		s.PrivateKey,
		hash[:],
	)

	if err != nil {
		panic(err)
	}

	return types.PartialSignature{
		SignerID:  s.ID,
		Signature: signature,
	}
}

func (s *Signer) Verify(
	message string,
	signature []byte,
) bool {

	hash := sha256.Sum256([]byte(message))

	return ecdsa.VerifyASN1(
		&s.PrivateKey.PublicKey,
		hash[:],
		signature,
	)
}