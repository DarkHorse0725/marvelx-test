package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"secure-vault/utils"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// EncryptWithEphemeralKyber encrypts the submitted key using Kyber and AES-GCM.
func EncryptWithEphemeralKyber(plainKey []byte) (
	ciphertext []byte,
	nonce []byte,
	kemCiphertext []byte,
	encPrivKey []byte,
	encPrivNonce []byte,
	pubKey []byte,
	err error,
) {
	var kem oqs.KeyEncapsulation

	// 1. Init Kyber
	if err = kem.Init("Kyber512", nil); err != nil {
		return
	}
	defer kem.Clean()

	// 2. Generate keypair
	pubKey, err = kem.GenerateKeyPair()
	if err != nil {
			return
	}
	
	// Export the secret key manually (if you need to save it)
	privKey := kem.ExportSecretKey()
	// 3. Encapsulate shared secret
	kemCiphertext, sharedSecret, err := kem.EncapSecret(pubKey)
	if err != nil {
		return
	}

	// 4. Derive AES key
	aesKey := sha256.Sum256(sharedSecret)
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	// 5. Encrypt plainKey using AES-GCM
	nonce = make([]byte, aesgcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return
	}
	ciphertext = aesgcm.Seal(nil, nonce, plainKey, nil)

	// 6. Encrypt ephemeral private key using server AES key
	encPrivKey, encPrivNonce, err = utils.EncryptWithMasterKey(privKey)
	return
}

// DecryptWithEphemeralKyber decrypts a key using Kyber + AES-GCM.
func DecryptWithEphemeralKyber(
	ciphertext []byte,
	nonce []byte,
	kemCiphertext []byte,
	encPrivKey []byte,
	encPrivNonce []byte,
) ([]byte, error) {
	// 1. Decrypt ephemeral private key
	privKey, err := utils.DecryptWithMasterKey(encPrivKey, encPrivNonce)
	if err != nil {
		return nil, err
	}

	var kem oqs.KeyEncapsulation
	// 2. Re-init Kyber with privKey
	if err := kem.Init("Kyber512", privKey); err != nil {
		return nil, err
	}
	defer kem.Clean()

	// 3. Decapsulate shared secret
	sharedSecret, err := kem.DecapSecret(kemCiphertext)
	if err != nil {
		return nil, err
	}

	// 4. Decrypt AES-GCM
	aesKey := sha256.Sum256(sharedSecret)
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
