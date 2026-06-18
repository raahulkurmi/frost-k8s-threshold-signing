package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/bytemare/frost"

	"frost-k8s-threshold-signing/internal/api"
	"frost-k8s-threshold-signing/internal/coordinatorstate"
	"frost-k8s-threshold-signing/internal/grpcserver"
	"frost-k8s-threshold-signing/internal/mtls"
	"frost-k8s-threshold-signing/internal/signing"
)

var signerAddresses = []string{
	getEnv("SIGNER_1_ADDR", "https://signer-1:8081"),
	getEnv("SIGNER_2_ADDR", "https://signer-2:8082"),
	getEnv("SIGNER_3_ADDR", "https://signer-3:8083"),
	getEnv("SIGNER_4_ADDR", "https://signer-4:8084"),
	getEnv("SIGNER_5_ADDR", "https://signer-5:8085"),
}

const threshold = 3

var (
	socketPath   = getEnv("SOCKET_PATH", "/var/run/frost-k8s/signer.sock")
	tcpAddr      = getEnv("TCP_ADDR", "")
	keyID        = getEnv("KEY_ID", "frost-k8s-v1")
	ecdsaKeyPath = getEnv("ECDSA_KEY_PATH", "data/ecdsa-signing.pem")
	tlsCert      = getEnv("TLS_CERT", "certs/proxy.crt")
	tlsKey       = getEnv("TLS_KEY", "certs/proxy.key")
	tlsCA        = getEnv("TLS_CA", "certs/ca.crt")
)

var httpClient *http.Client

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// collectCommitmentsParallel collects commitments from all signers in parallel.
// FIX: Collects ALL results before selecting threshold — prevents goroutine leaks.
func collectCommitmentsParallel() ([]api.CommitmentResponse, []string, error) {
	type result struct {
		commitment api.CommitmentResponse
		addr       string
		err        error
	}

	// Buffer = all signers so no goroutine ever blocks on send
	results := make(chan result, len(signerAddresses))

	for _, addr := range signerAddresses {
		go func(a string) {
			resp, err := httpClient.Post(a+"/commit", "application/json", nil)
			if err != nil {
				results <- result{addr: a, err: err}
				return
			}
			defer resp.Body.Close()
			var c api.CommitmentResponse
			if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
				results <- result{addr: a, err: err}
				return
			}
			results <- result{commitment: c, addr: a}
		}(addr)
	}

	// Collect ALL results — no early break, all goroutines finish cleanly
	var commitments []api.CommitmentResponse
	var activeSigners []string

	for i := 0; i < len(signerAddresses); i++ {
		r := <-results
		if r.err != nil {
			fmt.Printf("[proxy] Signer %s unavailable: %v\n", r.addr, r.err)
			continue
		}
		// Only keep up to threshold — extras discarded but goroutine already done
		if len(commitments) < threshold {
			commitments = append(commitments, r.commitment)
			activeSigners = append(activeSigners, r.addr)
		}
	}

	if len(commitments) < threshold {
		return nil, nil, fmt.Errorf("not enough signers: got %d, need %d", len(commitments), threshold)
	}

	return commitments, activeSigners, nil
}

// collectSharesParallel collects signature shares from active signers in parallel.
func collectSharesParallel(message string, commitments []api.CommitmentResponse, activeSigners []string) ([]api.SignatureShareResponse, error) {
	reqBody, _ := json.Marshal(api.SignRequest{Message: message, Commitments: commitments})

	type result struct {
		share api.SignatureShareResponse
		err   error
	}

	// Buffer = active signers so no goroutine blocks
	results := make(chan result, len(activeSigners))
	var mu sync.Mutex
	_ = mu

	for _, addr := range activeSigners {
		go func(a string) {
			resp, err := httpClient.Post(a+"/sign", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				results <- result{err: fmt.Errorf("sign from %s: %w", a, err)}
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			var share api.SignatureShareResponse
			if err := json.Unmarshal(b, &share); err != nil {
				results <- result{err: fmt.Errorf("decode share from %s: %w", a, err)}
				return
			}
			results <- result{share: share}
		}(addr)
	}

	var shares []api.SignatureShareResponse
	for i := 0; i < len(activeSigners); i++ {
		r := <-results
		if r.err != nil {
			return nil, r.err
		}
		shares = append(shares, r.share)
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

func makeSignFn(ecKey *signing.ECDSAKey) grpcserver.ThresholdSignFn {
	return func(claimsB64 []byte) (string, string, error) {
		payload := string(claimsB64)
		headerJSON := []byte(fmt.Sprintf(`{"alg":"ES256","typ":"JWT","kid":"%s"}`, keyID))
		header := encodeBase64URL(headerJSON)
		signingInput := header + "." + payload

		// Step 1: Collect commitments from threshold signers (parallel)
		commitments, activeSigners, err := collectCommitmentsParallel()
		if err != nil {
			return "", "", err
		}

		// Step 2: Collect signature shares (parallel)
		shares, err := collectSharesParallel(signingInput, commitments, activeSigners)
		if err != nil {
			return "", "", err
		}

		// Step 3: FROST aggregation — verify threshold signature is valid
		// This validates that t-of-n signers genuinely collaborated
		_, err = aggregateSignature(signingInput, commitments, shares)
		if err != nil {
			return "", "", fmt.Errorf("frost aggregate: %w", err)
		}

		// Step 4: ECDSA sign for K8s JWT verification compatibility
		// (K8s uses go-jose which requires ECDSA/ES256 format)
		signature, err := ecKey.SignES256(signingInput)
		if err != nil {
			return "", "", fmt.Errorf("ecdsa sign: %w", err)
		}

		fmt.Fprintf(os.Stderr, "[proxy] Signed JWT — kid=%s active_signers=%v\n", keyID, activeSigners)
		return header, signature, nil
	}
}

func main() {
	if err := coordinatorstate.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	var err error
	httpClient, err = mtls.NewClient(tlsCert, tlsKey, tlsCA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR loading mTLS certs: %v\n", err)
		os.Exit(1)
	}

	ecKey, err := signing.NewECDSAKey(ecdsaKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	pkix, err := ecKey.PublicKeyPKIX()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	srv, err := grpcserver.New(makeSignFn(ecKey), keyID, pkix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	if tcpAddr != "" {
		fmt.Printf("[proxy] TCP mode — addr=%s key=%s threshold=%d\n", tcpAddr, keyID, threshold)
		if err := grpcserver.ListenAndServeTCP(tcpAddr, srv); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	_ = os.MkdirAll("/var/run/frost-k8s", 0750)
	fmt.Printf("[proxy] Unix mode — socket=%s key=%s threshold=%d\n", socketPath, keyID, threshold)
	if err := grpcserver.ListenAndServe(socketPath, srv); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}