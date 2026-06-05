package types

type SignRequest struct {
	Message string
}

type PartialSignature struct {
	SignerID string
	Signature string
}
