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
	"frost-k8s-threshold-signing/internal/keystore"
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

// loadKeysData loads frost-keys data from encrypted file, plain file, or Vault
func loadKeysData(signerID int) ([]byte, string, error) {
	password := os.Getenv("FROST_KEY_PASSWORD")
	if password == "" {
		password = "frost-dev-password"
	}

	// Try Vault first
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultAddr != "" && vaultToken != "" {
		share, err := loadShareFromVault(vaultAddr, vaultToken, signerID)
		if err == nil {
			return nil, share, nil
		}
		fmt.Printf("[vault] Failed, trying local: %v\n", err)
	}

	// Try encrypted file
	if _, err := os.Stat("data/frost-keys.enc"); err == nil {
		data, err := keystore.LoadDecryptedKeys("data/frost-keys.enc", password)
		if err == nil {
			fmt.Println("[keystore] Loaded encrypted key file")
			return data, "", nil
		}
		fmt.Printf("[keystore] Failed to decrypt: %v\n", err)
	}

	// Fallback to plain file
	fmt.Println("[signer] Loading key share from plain file (not recommended for production)")
	data, err := os.ReadFile("data/frost-keys.json")
	if err != nil {
		return nil, "", fmt.Errorf("open frost-keys.json: %w", err)
	}
	return data, "", nil
}

func Init() error {
	signerID, err := strconv.Atoi(config.SignerID())
	if err != nil {
		return fmt.Errorf("parse signer id: %w", err)
	}

	keysData, directShare, err := loadKeysData(signerID)
	if err != nil {
		return err
	}

	var stored StoredKeys

	if directShare != "" {
		// Share came from Vault directly — still need full config from file
		data, err := os.ReadFile("data/frost-keys.json")
		if err != nil {
			// Try encrypted
			password := os.Getenv("FROST_KEY_PASSWORD")
			if password == "" {
				password = "frost-dev-password"
			}
			data, err = keystore.LoadDecryptedKeys("data/frost-keys.enc", password)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
		}
		if err := json.Unmarshal(data, &stored); err != nil {
			return fmt.Errorf("decode json: %w", err)
		}
		// Replace share with Vault share
		shareIndex := signerID - 1
		if shareIndex >= 0 && shareIndex < len(stored.Shares) {
			stored.Shares[shareIndex] = directShare
		}
	} else {
		if err := json.Unmarshal(keysData, &stored); err != nil {
			return fmt.Errorf("decode json: %w", err)
		}
	}

	var keyShares []*keys.KeyShare
	var publicShares []*keys.PublicKeyShare

	for _, shareHex := range stored.Shares {
		ks := &keys.KeyShare{}
		if err := ks.DecodeHex(shareHex); err != nil {
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

	shareIndex := signerID - 1
	signer, err := frostConfig.Signer(keyShares[shareIndex])
	if err != nil {
		return fmt.Errorf("create signer: %w", err)
	}

	fmt.Println("Loaded signer", signer.Identifier())
	Signer = signer
	Config = frostConfig
	return nil
}
