package coordinator

import (
	"fmt"

	"frost-k8s-threshold-signing/internal/signer"
	"frost-k8s-threshold-signing/internal/types"
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

	var signatures []types.PartialSignature

	for _, s := range c.Signers {

		partial := s.Sign(message)

		signatures = append(
			signatures,
			partial,
		)

		valid := s.Verify(
			message,
			partial.Signature,
		)

		fmt.Printf(
			"Verification by %s: %v\n",
			partial.SignerID,
			valid,
		)

		if len(signatures) >= c.Threshold {

			break
		}
	}

	fmt.Println()
fmt.Println("Threshold reached")

finalSig := c.Aggregate(signatures)

fmt.Println()
fmt.Println("Aggregation complete")

fmt.Printf(
	"Participants: %v\n",
	finalSig.Participants,
)

fmt.Printf(
	"Signature Count: %d\n",
	finalSig.Count,
)
}

func (c *Coordinator) Aggregate(
	signatures []types.PartialSignature,
) types.FinalSignature {

	var participants []string

	for _, sig := range signatures {

		participants = append(
			participants,
			sig.SignerID,
		)
	}

	return types.FinalSignature{
		Participants: participants,
		Count:        len(participants),
	}
}