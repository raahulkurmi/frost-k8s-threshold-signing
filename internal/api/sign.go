package api

type SignRequest struct {
	Message     string               `json:"message"`
	Commitments []CommitmentResponse `json:"commitments"`
}

type SignatureShareResponse struct {
	SignerID uint16 `json:"signer_id"`
	Share    string `json:"share"`
}