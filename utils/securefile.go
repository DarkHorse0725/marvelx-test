package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

var masterAESKey []byte

// LoadAESKey loads the AES key from the environment variable `PRIVATE_KEY_AES`
func LoadAESKey() error {
	keyHex := os.Getenv("PRIVATE_KEY_AES")
	if keyHex == "" {
		return errors.New("PRIVATE_KEY_AES not set in environment")
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return err
	}

	if len(key) != 32 {
		return errors.New("PRIVATE_KEY_AES must be 32 bytes (64 hex characters)")
	}

	masterAESKey = key
	return nil
}

// EncryptWithMasterKey encrypts the data using AES-GCM with the loaded AES key
func EncryptWithMasterKey(plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(masterAESKey)
	if err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// DecryptWithMasterKey decrypts AES-GCM data using the loaded AES key
func DecryptWithMasterKey(ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterAESKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
