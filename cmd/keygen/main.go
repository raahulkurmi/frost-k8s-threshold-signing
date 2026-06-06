package main

import (
	"encoding/json"
	"os"

	secretsharing "github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"
	"github.com/bytemare/ecc"
	"github.com/bytemare/frost"

	"frost-k8s-threshold-signing/internal/froststate"
)

func main() {

	group := ecc.Ristretto255Sha512

	shares, err := secretsharing.Shard(
		group,
		nil,
		3,
		5,
	)

	if err != nil {
		panic(err)
	}

	var publicShares []*keys.PublicKeyShare

	for _, share := range shares {
		publicShares = append(
			publicShares,
			share.Public(),
		)
	}

	config := &frost.Configuration{
		Ciphersuite:           frost.Default,
		Threshold:             3,
		MaxSigners:            5,
		VerificationKey:       shares[0].VerificationKey,
		SignerPublicKeyShares: publicShares,
	}

	if err := config.Init(); err != nil {
		panic(err)
	}

	var stored froststate.StoredKeys

	stored.Config = config.Hex()

	for _, share := range shares {
		stored.Shares = append(
			stored.Shares,
			share.Hex(),
		)
	}

	file, err := os.Create(
		"data/frost-keys.json",
	)

	if err != nil {
		panic(err)
	}

	defer file.Close()

	if err := json.NewEncoder(file).Encode(
		stored,
	); err != nil {
		panic(err)
	}
}
