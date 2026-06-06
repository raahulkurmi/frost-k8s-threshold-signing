package froststate

type StoredKeys struct {
	Config string   `json:"config"`
	Shares []string `json:"shares"`
}