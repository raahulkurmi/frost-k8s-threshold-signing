package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/bytemare/frost"

	"frost-k8s-threshold-signing/internal/api"
	"frost-k8s-threshold-signing/internal/config"
	"frost-k8s-threshold-signing/internal/dkg"
	"frost-k8s-threshold-signing/internal/froststate"
)

var (
	dkgMu          sync.Mutex
	dkgParticipant *dkg.Participant
	dkgCommitment  *dkg.Commitment
	allCommitments []*dkg.Commitment
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
		fmt.Printf("[dkg] ERROR: %v\n", err)
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

func dkgRound1Handler(w http.ResponseWriter, r *http.Request) {
	dkgMu.Lock()
	defer dkgMu.Unlock()
	signerID, _ := strconv.Atoi(config.SignerID())
	dkgParticipant = dkg.NewParticipant(uint16(signerID), 3, 5)
	commitment, err := dkgParticipant.Round1()
	if err != nil {
		fmt.Printf("[dkg] ERROR: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dkgCommitment = commitment
	fmt.Printf("[dkg] Round1 complete — signer-%d commitment ready\n", signerID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(commitment)
}

func dkgCommitmentsHandler(w http.ResponseWriter, r *http.Request) {
	dkgMu.Lock()
	defer dkgMu.Unlock()
	var commitments []*dkg.Commitment
	if err := json.NewDecoder(r.Body).Decode(&commitments); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	allCommitments = commitments
	fmt.Printf("[dkg] Received %d commitments\n", len(commitments))
	w.WriteHeader(http.StatusOK)
}

func dkgRound2Handler(w http.ResponseWriter, r *http.Request) {
	dkgMu.Lock()
	defer dkgMu.Unlock()
	path := r.URL.Path
	toIDStr := path[len("/dkg/round2/"):]
	toID64, err := strconv.ParseUint(toIDStr, 10, 16)
	if err != nil {
		http.Error(w, "invalid toID", http.StatusBadRequest)
		return
	}
	pkg, err := dkgParticipant.Round2(uint16(toID64))
	if err != nil {
		fmt.Printf("[dkg] ERROR: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pkg)
}

func dkgFinalizeHandler(w http.ResponseWriter, r *http.Request) {
	dkgMu.Lock()
	defer dkgMu.Unlock()
	var shares []*dkg.SharePackage
	if err := json.NewDecoder(r.Body).Decode(&shares); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cs := frost.Default
	g := cs.Group()
	groupPubKey, err := dkg.ComputeGroupPublicKey(g, allCommitments)
	if err != nil {
		fmt.Printf("[dkg] ERROR: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	keyShare, err := dkgParticipant.Finalize(shares, allCommitments, groupPubKey, nil)
	if err != nil {
		fmt.Printf("[dkg] ERROR: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("[dkg] ✅ Signer-%d DKG complete! Share: %s...\n", dkgParticipant.ID, keyShare.Hex()[:16])
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"signer": fmt.Sprintf("%d", dkgParticipant.ID),
	})
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := froststate.Init(); err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/commit", commitHandler)
	mux.HandleFunc("/sign", signHandler)
	mux.HandleFunc("/dkg/round1", dkgRound1Handler)
	mux.HandleFunc("/dkg/commitments", dkgCommitmentsHandler)
	mux.HandleFunc("/dkg/round2/", dkgRound2Handler)
	mux.HandleFunc("/dkg/finalize", dkgFinalizeHandler)

	port := config.Port()
	certFile := getEnv("TLS_CERT", "certs/signer.crt")
	keyFile := getEnv("TLS_KEY", "certs/signer.key")
	caFile := getEnv("TLS_CA", "certs/ca.crt")

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		fmt.Printf("Signer listening on :%s (plain HTTP)\n", port)
		if err := http.ListenAndServe(":"+port, mux); err != nil {
			panic(err)
		}
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequestClientCert,
	}

	server := &http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	fmt.Printf("Signer listening on :%s (mTLS enabled)\n", port)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		panic(err)
	}
}
// This is handled in main() already
