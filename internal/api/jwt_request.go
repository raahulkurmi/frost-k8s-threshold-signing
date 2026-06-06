package api

import "encoding/json"

type ThresholdJWTRequest struct {
	Claims json.RawMessage `json:"claims"`
}