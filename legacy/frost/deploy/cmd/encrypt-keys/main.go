//go:build legacy

package main

import (
	"fmt"
	"os"

	"frost-k8s-threshold-signing/legacy/frost/internal/keystore"
)

func main() {
	password := os.Getenv("FROST_KEY_PASSWORD")
	if password == "" {
		fmt.Fprintln(os.Stderr, "ERROR: FROST_KEY_PASSWORD is not set")
		os.Exit(1)
	}

	if err := keystore.SaveEncryptedKeys(
		"data/frost-keys.json",
		"data/frost-keys.enc",
		password,
	); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[encrypt] Done! data/frost-keys.enc created")
	fmt.Println("[encrypt] Delete data/frost-keys.json in production")
}
