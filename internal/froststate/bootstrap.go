package froststate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"

	"frost-k8s-threshold-signing/internal/config"
)


// loadShareFromVault fetches key share from Vault
func loadShareFromVault(vaultAddr, vaultToken string, signerID int) (string, error) {
	url := fmt.Sprintf("%s/v1/frost/data/signer-%d", vaultAddr, signerID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", vaultToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Data struct {
			Data struct {
				Share string `json:"share"`
			} `json:"data"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse vault response: %w", err)
	}

	if result.Data.Data.Share == "" {
		return "", fmt.Errorf("empty share from vault")
	}

	fmt.Printf("[vault] Loaded key share for signer-%d\n", signerID)
	return result.Data.Data.Share, nil
}

func Init() error {
	signerID, err := strconv.Atoi(config.SignerID())
	if err != nil {
		return fmt.Errorf("parse signer id: %w", err)
	}

	// Try Vault first
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	var shareHex string

	if vaultAddr != "" && vaultToken != "" {
		shareHex, err = loadShareFromVault(vaultAddr, vaultToken, signerID)
		if err != nil {
			fmt.Printf("[vault] Failed, falling back to file: %v\n", err)
		}
	}

	// Fallback to file
	if shareHex == "" {
		fmt.Println("[signer] Loading key share from file")
		file, err := os.Open("data/frost-keys.json")
		if err != nil {
			return fmt.Errorf("open frost-keys.json: %w", err)
		}
		defer file.Close()

		var stored StoredKeys
		if err := json.NewDecoder(file).Decode(&stored); err != nil {
			return fmt.Errorf("decode json: %w", err)
		}

		shareIndex := signerID - 1
		if shareIndex < 0 || shareIndex >= len(stored.Shares) {
			return fmt.Errorf("invalid signer id %d", signerID)
		}
		shareHex = stored.Shares[shareIndex]
	}

	// Load all public shares for config (still from file)
	file, err := os.Open("data/frost-keys.json")
	if err != nil {
		return fmt.Errorf("open frost-keys.json for config: %w", err)
	}
	defer file.Close()

	var stored StoredKeys
	if err := json.NewDecoder(file).Decode(&stored); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}

	var keyShares []*keys.KeyShare
	var publicShares []*keys.PublicKeyShare

	for _, s := range stored.Shares {
		ks := &keys.KeyShare{}
		if err := ks.DecodeHex(s); err != nil {
			return fmt.Errorf("decode key share: %w", err)
		}
		keyShares = append(keyShares, ks)
		publicShares = append(publicShares, ks.Public())
	}

	frostConfig := &frost.Configuration{
		Ciphersuite:           frost.Default,
		Threshold:             3,
		MaxSigners:            5,
		VerificationKey:       keyShares[0].VerificationKey,
		SignerPublicKeyShares: publicShares,
	}

	if err := frostConfig.Init(); err != nil {
		return fmt.Errorf("init config: %w", err)
	}

	// Load the specific signer's key share
	myShare := &keys.KeyShare{}
	if err := myShare.DecodeHex(shareHex); err != nil {
		return fmt.Errorf("decode my share: %w", err)
	}

	signer, err := frostConfig.Signer(myShare)
	if err != nil {
		return fmt.Errorf("create signer: %w", err)
	}

	fmt.Println("Loaded signer", signer.Identifier())

	Signer = signer
	Config = frostConfig

	return nil
}
