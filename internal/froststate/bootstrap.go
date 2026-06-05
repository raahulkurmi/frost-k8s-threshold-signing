package froststate

import (
	"strconv"
	secretsharing "github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"
	"github.com/bytemare/ecc"
	"github.com/bytemare/frost"
	

	"frost-k8s-threshold-signing/internal/config"
)

func Init() error {

	group := ecc.Ristretto255Sha512

	shares, err := secretsharing.Shard(
		group,
		nil,
		3,
		5,
	)

	if err != nil {
		return err
	}

	var publicShares []*keys.PublicKeyShare

	for _, share := range shares {
		publicShares = append(
			publicShares,
			share.Public(),
		)
	}

	frostConfig := &frost.Configuration{
		Ciphersuite:           frost.Default,
		Threshold:             3,
		MaxSigners:            5,
		VerificationKey:       shares[0].VerificationKey,
		SignerPublicKeyShares: publicShares,
	}

	if err := frostConfig.Init(); err != nil {
		return err
	}


	signerID, err := strconv.Atoi(
	config.SignerID(),
)

if err != nil {
	return err
}

shareIndex := signerID - 1

	signer, err := frostConfig.Signer(
		shares[shareIndex],
	)

	if err != nil {
		return err
	}

	Signer = signer
	println(
	"Loaded signer",
	signer.Identifier(),
)

	return nil
}