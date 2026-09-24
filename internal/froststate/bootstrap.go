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

// requirePassword returns FROST_KEY_PASSWORD or an error. There is no default:
// a missing password aborts startup (fail closed).
func requirePassword() (string, error) {
	password := os.Getenv("FROST_KEY_PASSWORD")
	if password == "" {
		return "", fmt.Errorf("FROST_KEY_PASSWORD is not set")
	}
	return password, nil
}

// loadKeysData loads frost-keys data from Vault (if VAULT_ADDR is set) or the
// encrypted file. Every failure is fatal; there is no fallback.
func loadKeysData(signerID int) ([]byte, string, error) {
	if vaultAddr := os.Getenv("VAULT_ADDR"); vaultAddr != "" {
		vaultToken := os.Getenv("VAULT_TOKEN")
		if vaultToken == "" {
			return nil, "", fmt.Errorf("VAULT_ADDR is set but VAULT_TOKEN is not")
		}
		share, err := loadShareFromVault(vaultAddr, vaultToken, signerID)
		if err != nil {
			return nil, "", fmt.Errorf("vault: %w", err)
		}
		return nil, share, nil
	}

	password, err := requirePassword()
	if err != nil {
		return nil, "", err
	}
	data, err := keystore.LoadDecryptedKeys("data/frost-keys.enc", password)
	if err != nil {
		return nil, "", fmt.Errorf("load encrypted key file: %w", err)
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
		password, err := requirePassword()
		if err != nil {
			return err
		}
		data, err := keystore.LoadDecryptedKeys("data/frost-keys.enc", password)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
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

	// Build signer pool for concurrent request handling
	pool := &SignerPool{ch: make(chan *frost.Signer, PoolSize)}
	for i := 0; i < PoolSize; i++ {
		s, err := frostConfig.Signer(keyShares[shareIndex])
		if err != nil {
			return fmt.Errorf("create pool signer %d: %w", i, err)
		}
		pool.ch <- s
	}
	Pool = pool
	fmt.Printf("[pool] Signer pool initialized with %d instances\n", PoolSize)
	return nil
}
