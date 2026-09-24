//go:build legacy

package api

type CommitmentCollection struct {
	Commitments []CommitmentResponse `json:"commitments"`
}