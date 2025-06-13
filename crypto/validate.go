package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func ValidatePublicKey(data []byte, keyType string) error {
	switch keyType {
	case "secp256k1":
		_, err := secp256k1.ParsePubKey(data)
		if err != nil {
			return errors.New("invalid secp256k1 public key")
		}
		return nil

	case "ed25519":
		if len(data) != ed25519.PublicKeySize {
			return errors.New("invalid ed25519 public key length")
		}
		return nil

	case "rsa":
		block, _ := pem.Decode(data)
		if block == nil {
			return errors.New("invalid PEM-encoded RSA key")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return errors.New("invalid RSA key format")
		}
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return errors.New("not an RSA public key")
		}
		return nil
	case "kyber512":
		return nil // TODO
	case "kyber768":
		return nil // TODO
	case "kyber1024":
		return nil // TODO
	default:
		return errors.New("unsupported key type")
	}
}
