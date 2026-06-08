package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"frost-k8s-threshold-signing/internal/dkg"
)

var signerAddresses = []string{
	getEnv("SIGNER_1_ADDR", "https://signer-1:8081"),
	getEnv("SIGNER_2_ADDR", "https://signer-2:8082"),
	getEnv("SIGNER_3_ADDR", "https://signer-3:8083"),
	getEnv("SIGNER_4_ADDR", "https://signer-4:8084"),
	getEnv("SIGNER_5_ADDR", "https://signer-5:8085"),
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getJSON(url string, out interface{}) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return json.Unmarshal(b, out)
}

func postJSON(url string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		b, _ := io.ReadAll(resp.Body)
		return json.Unmarshal(b, out)
	}
	return nil
}

func main() {
	fmt.Println("=== FROST Distributed DKG Ceremony ===")
	fmt.Printf("Signers: %d, Threshold: 3\n", len(signerAddresses))

	fmt.Println("\n[Round 1] Collecting commitments...")
	var allCommitments []*dkg.Commitment

	for i, addr := range signerAddresses {
		var c dkg.Commitment
		if err := getJSON(addr+"/dkg/round1", &c); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: signer %d round1: %v\n", i+1, err)
			os.Exit(1)
		}
		allCommitments = append(allCommitments, &c)
		fmt.Printf("  ✅ Commitment received from signer-%d\n", i+1)
	}

	fmt.Println("\n[Broadcast] Sending all commitments to signers...")
	for i, addr := range signerAddresses {
		if err := postJSON(addr+"/dkg/commitments", allCommitments, nil); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: broadcast to signer %d: %v\n", i+1, err)
			os.Exit(1)
		}
		fmt.Printf("  ✅ Commitments sent to signer-%d\n", i+1)
	}

	fmt.Println("\n[Round 2] Distributing shares...")
	sharesByTarget := make(map[uint16][]*dkg.SharePackage)

	for i, addr := range signerAddresses {
		for j := range signerAddresses {
			toID := uint16(j + 1)
			var pkg dkg.SharePackage
			if err := getJSON(fmt.Sprintf("%s/dkg/round2/%d", addr, toID), &pkg); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: signer %d round2 for %d: %v\n", i+1, toID, err)
				os.Exit(1)
			}
			sharesByTarget[toID] = append(sharesByTarget[toID], &pkg)
		}
		fmt.Printf("  ✅ Shares collected from signer-%d\n", i+1)
	}

	fmt.Println("\n[Distribute] Sending shares to signers...")
	for i, addr := range signerAddresses {
		toID := uint16(i + 1)
		if err := postJSON(addr+"/dkg/finalize", sharesByTarget[toID], nil); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: finalize signer %d: %v\n", i+1, err)
			os.Exit(1)
		}
		fmt.Printf("  ✅ Shares delivered to signer-%d\n", i+1)
	}

	fmt.Println("\n=== DKG Ceremony Complete ===")
	fmt.Println("Each signer now holds an independent key share.")
	fmt.Println("No single party ever saw the complete signing key.")
}
