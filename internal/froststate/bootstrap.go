package froststate

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"

	"frost-k8s-threshold-signing/internal/config"
)

func Init() error {

	file, err := os.Open(
		"data/frost-keys.json",
	)

	if err != nil {
		return fmt.Errorf(
			"open frost-keys.json: %w",
			err,
		)
	}

	defer file.Close()

	var stored StoredKeys

	if err := json.NewDecoder(file).Decode(
		&stored,
	); err != nil {
		return fmt.Errorf(
			"decode json: %w",
			err,
		)
	}

	fmt.Println(
		"Share count:",
		len(stored.Shares),
	)

	var keyShares []*keys.KeyShare
	var publicShares []*keys.PublicKeyShare

	for _, shareHex := range stored.Shares {

		keyShare := &keys.KeyShare{}

		if err := keyShare.DecodeHex(
			shareHex,
		); err != nil {
			return fmt.Errorf(
				"decode key share: %w",
				err,
			)
		}

		keyShares = append(
			keyShares,
			keyShare,
		)

		publicShares = append(
			publicShares,
			keyShare.Public(),
		)
	}

	frostConfig := &frost.Configuration{
		Ciphersuite:           frost.Default,
		Threshold:             3,
		MaxSigners:            5,
		VerificationKey:       keyShares[0].VerificationKey,
		SignerPublicKeyShares: publicShares,
	}

	if err := frostConfig.Init(); err != nil {
		return fmt.Errorf(
			"init config: %w",
			err,
		)
	}

	signerID, err := strconv.Atoi(
		config.SignerID(),
	)

	if err != nil {
		return fmt.Errorf(
			"parse signer id: %w",
			err,
		)
	}

	shareIndex := signerID - 1

	if shareIndex < 0 || shareIndex >= len(keyShares) {
		return fmt.Errorf(
			"invalid signer id %d",
			signerID,
		)
	}

	signer, err := frostConfig.Signer(
		keyShares[shareIndex],
	)

	if err != nil {
		return fmt.Errorf(
			"create signer: %w",
			err,
		)
	}

	fmt.Println(
		"Loaded signer",
		signer.Identifier(),
	)

	Signer = signer
	Config = frostConfig

	return nil
}