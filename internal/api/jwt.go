package api

type ThresholdJWTResponse struct {
	Header       string `json:"header"`
	Payload      string `json:"payload"`
	SigningInput string `json:"signing_input"`
	Signature    string `json:"signature"`
	Token        string `json:"token"`
}

type SignJWTResponse struct {
	Token string `json:"token"`
}