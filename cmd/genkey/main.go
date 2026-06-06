package main

import (
	"frost-k8s-threshold-signing/internal/signing"
)

func main() {
	_, err := signing.NewECDSAKey("data/ecdsa-signing.pem")
	if err != nil {
		panic(err)
	}
}
