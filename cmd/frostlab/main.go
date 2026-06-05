package main

import (
	"fmt"

	secretsharing "github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"
	"github.com/bytemare/ecc"
	"github.com/bytemare/frost"
)

func main() {

	group := ecc.Ristretto255Sha512

	shares, err := secretsharing.Shard(
		group,
		nil, // generate random secret
		3,   // threshold
		5,   // max signers
	)

	if err != nil {
		panic(err)
	}

	fmt.Printf("Generated %d key shares\n\n", len(shares))

	for _, share := range shares {

		fmt.Printf(
			"Signer ID: %d\n",
			share.Identifier(),
		)
	}

	fmt.Println()

	var publicShares []*keys.PublicKeyShare

	for _, share := range shares {

		publicShare := share.Public()

		publicShares = append(
			publicShares,
			publicShare,
		)

		fmt.Printf(
			"Public Share ID: %d\n",
			publicShare.ID,
		)
	}

	fmt.Printf(
		"\nCollected %d public key shares\n",
		len(publicShares),
	)

	fmt.Println()

	for _, share := range shares {

		fmt.Printf(
			"ID=%d PublicExists=%v SecretExists=%v\n",
			share.Identifier(),
			share.Public() != nil,
			share.SecretKey() != nil,
		)
		
	}
	fmt.Println()

for _, share := range shares {

	fmt.Printf(
		"ID=%d VerificationKeyExists=%v\n",
		share.Identifier(),
		share.VerificationKey != nil,
	)
}



fmt.Println()

config := &frost.Configuration{
	Ciphersuite:           frost.Default,
	Threshold:             3,
	MaxSigners:            5,
	VerificationKey:       shares[0].VerificationKey,
	SignerPublicKeyShares: publicShares,
}

err = config.Init()

if err != nil {
	panic(err)
}

fmt.Println("FROST configuration initialized successfully")



fmt.Println()

signer, err := config.Signer(
	shares[0],
)

if err != nil {
	panic(err)
}

fmt.Printf(
	"Created FROST signer with ID %d\n",
	signer.Identifier(),
)

commitment := signer.Commit()

fmt.Println()
fmt.Println("Commitment generated")

fmt.Printf(
	"Commitment ID: %d\n",
	commitment.CommitmentID,
)

fmt.Printf(
	"Signer ID: %d\n",
	commitment.SignerID,
)

}