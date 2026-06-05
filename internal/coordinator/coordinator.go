package coordinator

import (
	"fmt"

	"frost-k8s-threshold-signing/internal/signer"
)

type Coordinator struct {
	Signers   []*signer.Signer
	Threshold int
}

func New(
	signers []*signer.Signer,
	threshold int,
) *Coordinator {

	return &Coordinator{
		Signers:   signers,
		Threshold: threshold,
	}
}

func (c *Coordinator) Sign(message string) {

	fmt.Println("Coordinator received request")

	var partials []string

	for _, s := range c.Signers {

		signature := s.Sign(message)

		partials = append(partials, signature)

		if len(partials) >= c.Threshold {

			break
		}
	}

	fmt.Println()
	fmt.Println("Threshold reached")

	for _, p := range partials {

		fmt.Println(p)
	}
}