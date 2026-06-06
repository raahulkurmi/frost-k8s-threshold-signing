package coordinatorstate

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"

	"frost-k8s-threshold-signing/internal/froststate"
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

	var stored froststate.StoredKeys

	if err := json.NewDecoder(file).Decode(
		&stored,
	); err != nil {
		return fmt.Errorf(
			"decode json: %w",
			err,
		)
	}

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

	Config = frostConfig

	fmt.Println(
		"Coordinator FROST config loaded",
	)

	return nil
}