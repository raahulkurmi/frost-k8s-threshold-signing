package api

type CommitmentResponse struct {
	CommitmentID uint64 `json:"commitment_id"`
	SignerID     uint16 `json:"signer_id"`
	Commitment   string `json:"commitment"`
}