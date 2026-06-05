package coordinator

import (
	"fmt"

	"frost-k8s-threshold-signing/internal/signer"
)

type Coordinator struct {
	Signers []*signer.Signer
}

func New(signers []*signer.Signer) *Coordinator {
	return &Coordinator{
		Signers: signers,
	}
}

func (c *Coordinator) Sign(message string) {

	fmt.Println("Coordinator received request")

	for _, s := range c.Signers {

		signature := s.Sign(message)

		fmt.Println(signature)
	}
}