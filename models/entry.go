package models

import "time"

type VaultEntry struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Label      string    `json:"label"`
	KeyType    string    `json:"key_type"`    // e.g., "secp256k1", "rsa", etc.
	KeyEncoding string    `json:"key_encoding"` // e.g., "hex", "base64", etc.
	CryptoMode string    `json:"crypto_mode"` // "classical" or "quantum-safe"
	CreatedAt  time.Time `json:"created_at"`

	// Shared across both modes
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`

	// Classical mode fields (ECC)
	EphemeralPubKey            []byte `json:"ephemeral_pub_key"`
	EncryptedEphemeralPrivKey []byte `json:"encrypted_ephemeral_priv_key"`
	EphemeralPrivNonce        []byte `json:"ephemeral_priv_nonce"`

	// Quantum-safe mode fields (Kyber)
	KyberPubKey           []byte `json:"kyber_pub_key"`
	KyberCiphertext       []byte `json:"kyber_ciphertext"`
	EncryptedKyberPrivKey []byte `json:"encrypted_kyber_priv_key"`
	KyberPrivNonce        []byte `json:"kyber_priv_nonce"`
}
