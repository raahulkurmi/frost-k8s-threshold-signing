package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/bytemare/frost"

	"frost-k8s-threshold-signing/internal/api"
	"frost-k8s-threshold-signing/internal/config"
	"frost-k8s-threshold-signing/internal/froststate"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "signer alive")
}

func commitHandler(w http.ResponseWriter, r *http.Request) {
	froststate.Mu.Lock()
	defer froststate.Mu.Unlock()

	commitment := froststate.Signer.Commit()
	froststate.Commitments[commitment.CommitmentID] = commitment

	resp := api.CommitmentResponse{
		CommitmentID: commitment.CommitmentID,
		SignerID:     commitment.SignerID,
		Commitment:   commitment.Hex(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	froststate.Mu.Lock()
	defer froststate.Mu.Unlock()

	var req api.SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var commitments frost.CommitmentList
	for _, item := range req.Commitments {
		commitment := &frost.Commitment{}
		if err := commitment.DecodeHex(item.Commitment); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		commitments = append(commitments, commitment)
	}
	commitments.Sort()

	sigShare, err := froststate.Signer.Sign([]byte(req.Message), commitments)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := api.SignatureShareResponse{
		SignerID: sigShare.SignerIdentifier,
		Share:    sigShare.Hex(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	if err := froststate.Init(); err != nil {
		panic(err)
	}

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/commit", commitHandler)
	http.HandleFunc("/sign", signHandler)

	port := config.Port()

	// mTLS configuration
	certFile := getEnv("TLS_CERT", "certs/signer.crt")
	keyFile  := getEnv("TLS_KEY", "certs/signer.key")
	caFile   := getEnv("TLS_CA", "certs/ca.crt")

	// Load CA for client verification
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		fmt.Printf("[signer] No CA found, starting without mTLS: %v\n", err)
		fmt.Printf("Signer listening on :%s (plain HTTP)\n", port)
		if err := http.ListenAndServe(":"+port, nil); err != nil {
			panic(err)
		}
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
	}

	fmt.Printf("Signer listening on :%s (mTLS enabled)\n", port)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		panic(err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
