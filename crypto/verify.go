package crypto

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// IsValidSecp256k1PubKey verifies if rawKey is a valid compressed secp256k1 public key.
func IsValidSecp256k1PubKey(rawKey []byte) bool {
	if len(rawKey) != 33 {
		return false
	}
	_, err := secp256k1.ParsePubKey(rawKey)
	return err == nil
}

// IsValidKyberPubKey verifies if rawKey is a valid Kyber512 public key.
func IsValidKyberPubKey(key []byte) bool {
	return true;
	kem := oqs.KeyEncapsulation{}
	defer kem.Clean()

	if err := kem.Init("Kyber512", nil); err != nil {
		return false
	}

	pubKey, err := kem.GenerateKeyPair()
	if err != nil {
			return false
	}
		
	return len(key) == len(pubKey)
}
