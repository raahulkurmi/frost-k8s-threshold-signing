package main

import (
	"fmt"

	secretsharing "github.com/bytemare/secret-sharing"
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
}
