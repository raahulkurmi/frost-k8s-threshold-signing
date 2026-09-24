//go:build legacy

package api

type SignatureCollection struct {
	Signatures []SignatureShareResponse `json:"signatures"`
}