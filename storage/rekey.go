package storage

import (
	"encoding/json"
	"errors"

	"secure-vault/crypto"
	"secure-vault/models"
	"secure-vault/utils"

	"go.etcd.io/bbolt"
)

func ReEncryptAllVaultEntries(newMode models.CryptoMode) error {
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(vaultBucket))
		if b == nil {
			return errors.New("vault bucket not found")
		}

		return b.ForEach(func(k, v []byte) error {
			var entry models.VaultEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}

			var plainKey []byte
			var err error

			// Decrypt based on old mode
			utils.Info("rekey", "decrypting key with old mode: %s %v", entry.CryptoMode, entry)
			switch entry.CryptoMode {
			case string(models.ClassicalMode):
				plainKey, err = crypto.DecryptWithEphemeralECC(
					entry.Ciphertext,
					entry.Nonce,
					entry.EncryptedEphemeralPrivKey,
					entry.EphemeralPrivNonce,
				)
				if err != nil {
					utils.Error("rekey", "failed to ECC decrypt key: %v", err)
					return err
				}
			case string(models.QuantumSafeMode):
				plainKey, err = crypto.DecryptWithEphemeralKyber(
					entry.Ciphertext,
					entry.Nonce,
					entry.KyberCiphertext,
					entry.EncryptedKyberPrivKey,
					entry.KyberPrivNonce,
				)
				if err != nil {
					utils.Error("rekey", "failed to KEM decrypt key: %v", err)
					return err
					
				}
			default:
				return errors.New("invalid crypto_mode: " + entry.CryptoMode)
			}
			if err != nil {
				return err
			}

			// Re-encrypt based on new mode
			switch newMode {
			case models.ClassicalMode:
				entry.Ciphertext,
					entry.Nonce,
					entry.EncryptedEphemeralPrivKey,
					entry.EphemeralPrivNonce,
					entry.EphemeralPubKey,
					err = crypto.EncryptWithEphemeralECC(plainKey)

					if err != nil {
						utils.Error("rekey", "failed to ECC encrypt  key: %v", err)
						return err
					}
				// Cleanup quantum-safe fields
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
					err = crypto.EncryptWithEphemeralKyber(plainKey)
					if err != nil {
						utils.Error("rekey", "failed to KEM encrypt key: %v", err)
						return err
					}
				// Cleanup classical fields
				entry.EphemeralPubKey = nil
				entry.EncryptedEphemeralPrivKey = nil
				entry.EphemeralPrivNonce = nil

			default:
				return errors.New("unsupported crypto_mode: " + string(newMode))
			}
			if err != nil {
				return err
			}

			entry.CryptoMode = string(newMode) // for further extensibility

			updated, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			return b.Put(k, updated)
		})
	})
}
