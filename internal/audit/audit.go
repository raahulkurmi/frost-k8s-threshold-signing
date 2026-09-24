// Package audit appends one JSON line per signer decision to a local file.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is one audit record. It never contains the signature share.
type Entry struct {
	Time               time.Time `json:"ts"`
	SignerID           int       `json:"signer_id"`
	RequestID          string    `json:"request_id"`
	SigningInputSHA256 string    `json:"signing_input_sha256,omitempty"`
	Sub                string    `json:"sub,omitempty"`
	Aud                []string  `json:"aud,omitempty"`
	Client             string    `json:"client,omitempty"` // authenticated peer SAN
	Decision           string    `json:"decision"`         // "allow" or "deny"
	Reason             string    `json:"reason,omitempty"`
}

// Log is an append-only JSON-lines file, safe for concurrent use.
type Log struct {
	mu sync.Mutex
	f  *os.File
}

// Open opens path for appending (created 0600). An empty path is an error.
func Open(path string) (*Log, error) {
	if path == "" {
		return nil, errors.New("audit: path is empty")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return &Log{f: f}, nil
}

// Write appends e. A write failure is returned so the caller can fail closed.
func (l *Log) Write(e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.f.Write(b)
	return err
}

// Close closes the file.
func (l *Log) Close() error { return l.f.Close() }
