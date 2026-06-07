package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type EncryptedStore struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// deriveKey derives a 32-byte AES key from password
func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// Encrypt encrypts data with AES-256-GCM
func Encrypt(data []byte, password string) ([]byte, error) {
	key := deriveKey(password)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	store := EncryptedStore{
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ciphertext),
	}

	return json.Marshal(store)
}

// Decrypt decrypts data with AES-256-GCM
func Decrypt(encryptedData []byte, password string) ([]byte, error) {
	var store EncryptedStore
	if err := json.Unmarshal(encryptedData, &store); err != nil {
		return nil, fmt.Errorf("parse encrypted store: %w", err)
	}

	key := deriveKey(password)

	nonce, err := hex.DecodeString(store.Nonce)
	if err != nil {
		return nil, err
	}

	ciphertext, err := hex.DecodeString(store.Ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	return plaintext, nil
}

// SaveEncryptedKeys encrypts and saves frost-keys.json
func SaveEncryptedKeys(keysFile, encryptedFile, password string) error {
	data, err := os.ReadFile(keysFile)
	if err != nil {
		return fmt.Errorf("read keys file: %w", err)
	}

	encrypted, err := Encrypt(data, password)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := os.WriteFile(encryptedFile, encrypted, 0600); err != nil {
		return fmt.Errorf("write encrypted file: %w", err)
	}

	fmt.Printf("[keystore] Keys encrypted and saved to %s\n", encryptedFile)
	return nil
}

// LoadDecryptedKeys loads and decrypts frost-keys.json
func LoadDecryptedKeys(encryptedFile, password string) ([]byte, error) {
	data, err := os.ReadFile(encryptedFile)
	if err != nil {
		return nil, fmt.Errorf("read encrypted file: %w", err)
	}

	return Decrypt(data, password)
}
