package handlers

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"secure-vault/crypto"
	"secure-vault/middleware"
	"secure-vault/models"
	"secure-vault/storage"
	"secure-vault/utils"

	"github.com/gorilla/mux"

	"github.com/google/uuid"
)

type storeRequest struct {
	Key         string `json:"key"`          // string-encoded key
	Label       string `json:"label"`
	KeyType  string `json:"key_type"`  // "secp256k1" or "kyber512"
	KeyEncoding string `json:"key_encoding"` // "hex" or "string"
}
func StoreKey(w http.ResponseWriter, r *http.Request) {
	UserId := middleware.GetUserIDFromContext(r)
	var payload storeRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mode, err := storage.GetCryptoMode()
	if err != nil {
		http.Error(w, "Cannot read crypto mode", http.StatusInternalServerError)
		return
	}

	var decodedKey []byte
	switch payload.KeyEncoding {
	case "hex":
		decodedKey, err = hex.DecodeString(payload.Key)
	case "string":
		decodedKey = []byte(payload.Key)
	default:
		http.Error(w, "Invalid key encoding", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Println(err)
		http.Error(w, "Invalid key format", http.StatusBadRequest)
		return
	}

	if err := crypto.ValidatePublicKey(decodedKey, payload.KeyType); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	entry := models.VaultEntry{
		ID:         uuid.NewString(),
		Label:      payload.Label,
		UserID:     UserId,
		KeyType:    payload.KeyType,
		KeyEncoding: payload.KeyEncoding,
		CryptoMode: string(mode),
		CreatedAt:  utils.Now(),
	}

	switch mode {
	case models.ClassicalMode:
		ct, nonce, encPriv, encPrivNonce, pub, err := crypto.EncryptWithEphemeralECC(decodedKey)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}
		entry.Ciphertext = ct
		entry.Nonce = nonce
		entry.EncryptedEphemeralPrivKey = encPriv
		entry.EphemeralPrivNonce = encPrivNonce
		entry.EphemeralPubKey = pub

	case models.QuantumSafeMode:
		ct, nonce, kemCT, encPriv, encPrivNonce, pub, err := crypto.EncryptWithEphemeralKyber(decodedKey)
		if err != nil {
			http.Error(w, "Kyber encryption failed", http.StatusInternalServerError)
			return
		}
		entry.Ciphertext = ct
		entry.Nonce = nonce
		entry.KyberCiphertext = kemCT
		entry.EncryptedKyberPrivKey = encPriv
		entry.KyberPrivNonce = encPrivNonce
		entry.KyberPubKey = pub

	default:
		http.Error(w, "Unsupported crypto mode", http.StatusBadRequest)
		return
	}

	if err := storage.SaveKey(entry); err != nil {
		http.Error(w, "Failed to save entry", http.StatusInternalServerError)
		return
	}

	utils.Info("vault", "Stored key: id=%s user=%s", entry.ID, entry.UserID)

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": entry.ID})
}

func GetKey(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	entry, err := storage.GetKey(id)
	if err != nil {
		http.Error(w, "Vault entry not found", http.StatusNotFound)
		return
	}

	var plainKey []byte

	switch models.CryptoMode(entry.CryptoMode) {
	case models.ClassicalMode:
		plainKey, err = crypto.DecryptWithEphemeralECC(
			entry.Ciphertext,
			entry.Nonce,
			entry.EncryptedEphemeralPrivKey,
			entry.EphemeralPrivNonce,
		)
	case models.QuantumSafeMode:
		plainKey, err = crypto.DecryptWithEphemeralKyber(
			entry.Ciphertext,
			entry.Nonce,
			entry.KyberCiphertext,
			entry.EncryptedKyberPrivKey,
			entry.KyberPrivNonce,
		)
	default:
		http.Error(w, "Unsupported mode", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Decryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var encoded string
	switch entry.KeyEncoding {
	case "hex":
		encoded = hex.EncodeToString(plainKey)
	case "string":
		encoded = string(plainKey)
	default:
		http.Error(w, "Unsupported key_encoding", http.StatusInternalServerError)
		return
	}

	utils.Info("vault", "Get key: id=%s user=%s", id, entry.UserID)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"id":  entry.ID,
		"key": encoded,
	})
}
type rotateRequest struct {
	Key         string  `json:"key"`
	KeyType     string  `json:"key_type"`     // e.g. "secp256k1", "kyber"
	KeyEncoding string  `json:"key_encoding"` // "hex" or "string"`
}
func RotateKeyHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	// 1. Parse and decode body
	var req rotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// 2. Decode key based on encoding
	var rawKey []byte
	var err error
	switch req.KeyEncoding {
	case "hex":
		rawKey, err = hex.DecodeString(req.Key)
	case "string":
		rawKey = []byte(req.Key)
	default:
		http.Error(w, "Unsupported key_encoding", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Invalid key encoding data", http.StatusBadRequest)
		return
	}

	// 3. Validate key
	if err := crypto.ValidatePublicKey(rawKey, req.KeyType); err != nil {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}

	// 4. Get current mode
	mode, err := storage.GetCryptoMode()
	if err != nil {
		http.Error(w, "Could not determine current crypto mode", http.StatusInternalServerError)
		return
	}

	// 5. Encrypt new key
	entry, err := storage.GetKey(id)
	if err != nil {
		http.Error(w, "Vault entry not found", http.StatusNotFound)
		return
	}

	switch mode {
	case models.ClassicalMode:
		entry.Ciphertext,
			entry.Nonce,
			entry.EncryptedEphemeralPrivKey,
			entry.EphemeralPrivNonce,
			entry.EphemeralPubKey,
			err = crypto.EncryptWithEphemeralECC(rawKey)

		// clear kyber fields
		entry.KyberPubKey = nil
		entry.KyberCiphertext = nil
		entry.EncryptedKyberPrivKey = nil
		entry.KyberPrivNonce = nil

	case models.QuantumSafeMode:
		entry.Ciphertext,
			entry.Nonce,
			entry.KyberCiphertext,
			entry.EncryptedKyberPrivKey,
			entry.KyberPrivNonce,
			entry.KyberPubKey,
			err = crypto.EncryptWithEphemeralKyber(rawKey)

		// clear classical fields
		entry.EphemeralPubKey = nil
		entry.EncryptedEphemeralPrivKey = nil
		entry.EphemeralPrivNonce = nil

	default:
		http.Error(w, "Unsupported crypto mode", http.StatusInternalServerError)
		return
	}
	if err != nil {
		http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 6. Update vault entry in DB
	if err := storage.UpdateVaultEntry(id, &entry); err != nil {
		http.Error(w, "Failed to rotate key", http.StatusInternalServerError)
		return
	}

	utils.Info("vault", "Rotated key: id=%s user=%s", id, entry.UserID)

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Key rotated successfully",
		"id":      entry.ID,
	})
}
