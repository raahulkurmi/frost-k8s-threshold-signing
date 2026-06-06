package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/bytemare/frost"

	"frost-k8s-threshold-signing/internal/api"
	"frost-k8s-threshold-signing/internal/coordinatorstate"
	"frost-k8s-threshold-signing/internal/grpcserver"
)

var signerAddresses = []string{
	getEnv("SIGNER_1_ADDR", "http://localhost:8081"),
	getEnv("SIGNER_2_ADDR", "http://localhost:8082"),
	getEnv("SIGNER_3_ADDR", "http://localhost:8083"),
}

var (
	socketPath = getEnv("SOCKET_PATH", "/var/run/frost-k8s/signer.sock")
	keyID      = getEnv("KEY_ID", "frost-k8s-v1")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func collectCommitments() ([]api.CommitmentResponse, error) {
	var commitments []api.CommitmentResponse
	for _, addr := range signerAddresses {
		resp, err := http.Post(addr+"/commit", "application/json", nil)
		if err != nil {
			return nil, fmt.Errorf("commit from %s: %w", addr, err)
		}
		defer resp.Body.Close()
		var c api.CommitmentResponse
		if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
			return nil, fmt.Errorf("decode commitment: %w", err)
		}
		commitments = append(commitments, c)
	}
	return commitments, nil
}

func collectShares(message string, commitments []api.CommitmentResponse) ([]api.SignatureShareResponse, error) {
	reqBody, _ := json.Marshal(api.SignRequest{Message: message, Commitments: commitments})
	var shares []api.SignatureShareResponse
	for _, addr := range signerAddresses {
		resp, err := http.Post(addr+"/sign", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			return nil, fmt.Errorf("sign from %s: %w", addr, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var share api.SignatureShareResponse
		if err := json.Unmarshal(b, &share); err != nil {
			return nil, fmt.Errorf("decode share: %w", err)
		}
		shares = append(shares, share)
	}
	return shares, nil
}

func aggregateSignature(message string, commitments []api.CommitmentResponse, shares []api.SignatureShareResponse) (*frost.Signature, error) {
	var commitmentList frost.CommitmentList
	for _, item := range commitments {
		c := &frost.Commitment{}
		if err := c.DecodeHex(item.Commitment); err != nil {
			return nil, err
		}
		commitmentList = append(commitmentList, c)
	}
	commitmentList.Sort()

	var sigShares []*frost.SignatureShare
	for _, item := range shares {
		s := &frost.SignatureShare{}
		if err := s.DecodeHex(item.Share); err != nil {
			return nil, err
		}
		sigShares = append(sigShares, s)
	}

	return coordinatorstate.Config.AggregateSignatures([]byte(message), sigShares, commitmentList, true)
}

func generateThresholdJWT(payloadJSON []byte) (string, string, error) {
	headerJSON := []byte(fmt.Sprintf(`{"alg":"ES256","typ":"JWT","kid":"%s"}`, keyID))
	header := encodeBase64URL(headerJSON)
	payload := encodeBase64URL(payloadJSON)
	signingInput := header + "." + payload

	commitments, err := collectCommitments()
	if err != nil {
		return "", "", err
	}

	shares, err := collectShares(signingInput, commitments)
	if err != nil {
		return "", "", err
	}

	finalSig, err := aggregateSignature(signingInput, commitments, shares)
	if err != nil {
		return "", "", err
	}

	signature := encodeBase64URL([]byte(finalSig.Hex()))
	fmt.Printf("[proxy] Signed JWT — kid=%s\n", keyID)
	return header, signature, nil
}

func main() {
	if err := coordinatorstate.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	_ = os.MkdirAll("/var/run/frost-k8s", 0750)

	srv, err := grpcserver.New(generateThresholdJWT, keyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[proxy] socket=%s key=%s signers=%v\n", socketPath, keyID, signerAddresses)

	if err := grpcserver.ListenAndServe(socketPath, srv); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}
