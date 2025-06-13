package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"secure-vault/utils"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// EncryptWithEphemeralECC performs ECC-based envelope encryption
func EncryptWithEphemeralECC(plainKey []byte) (
	ciphertext []byte,
	nonce []byte,
	encPrivKey []byte,
	encPrivNonce []byte,
	ephPubKey []byte,
	err error,
) {
	// 1. Generate ephemeral ECC keypair
	ephPriv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return
	}
	ephPub := ephPriv.PubKey()

	// 2. Derive AES key from ephemeral private key
	aesKey := sha256.Sum256(ephPriv.Serialize())

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce = make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return
	}
	ciphertext = aesgcm.Seal(nil, nonce, plainKey, nil)

	// 3. Encrypt the ephemeral private key with server master AES key
	encPrivKey, encPrivNonce, err = utils.EncryptWithMasterKey(ephPriv.Serialize())
	if err != nil {
		return
	}

	// 4. Output
	ephPubKey = ephPub.SerializeCompressed()
	return
}


// DecryptWithEphemeralECC decrypts the stored key using the decrypted ephemeral ECC private key
func DecryptWithEphemeralECC(
	ciphertext []byte,
	nonce []byte,
	encPrivKey []byte,
	encPrivNonce []byte,
) ([]byte, error) {
	// 1. Decrypt the ephemeral private key
	privBytes, err := utils.DecryptWithMasterKey(encPrivKey, encPrivNonce)
	if err != nil {
		return nil, err
	}
	ephPriv := secp256k1.PrivKeyFromBytes(privBytes) 

	// 2. Derive AES key from private key
	aesKey := sha256.Sum256(ephPriv.Serialize())

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 3. Decrypt the submitted key
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
