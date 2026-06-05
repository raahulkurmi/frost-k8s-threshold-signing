package config

import "os"

func Port() string {

	port := os.Getenv("PORT")

	if port == "" {
		return "8081"
	}

	return port
}

func SignerID() string {

	id := os.Getenv("SIGNER_ID")

	if id == "" {
		return "1"
	}

	return id
}