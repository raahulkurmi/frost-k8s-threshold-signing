package main

import (
	"fmt"

	secretsharing "github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"
	"github.com/bytemare/ecc"
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
}