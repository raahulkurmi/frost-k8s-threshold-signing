package signer

import "fmt"

type Signer struct {
	ID string
}

func New(id string) *Signer {
	return &Signer{
		ID: id,
	}
}

func (s *Signer) Sign(message string) string {
	fmt.Printf("[%s] signing message: %s\n", s.ID, message)

	return fmt.Sprintf("signature-from-%s", s.ID)
}