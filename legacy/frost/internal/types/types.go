//go:build legacy

package types

type PartialSignature struct {
	SignerID  string
	Signature []byte
}

type FinalSignature struct {
	Participants []string
	Count        int
}