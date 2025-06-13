package storage

import (
	"errors"
	"secure-vault/models"

	"go.etcd.io/bbolt"
)

const (
	settingsBucket = "settings"
	modeKey        = "cryptomode"
	defaultMode    = models.ClassicalMode
)

// GetCryptoMode reads the current crypto mode from BoltDB
func GetCryptoMode() (models.CryptoMode, error) {
	var mode models.CryptoMode

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(settingsBucket))
		v := b.Get([]byte(modeKey))
		if v == nil {
			mode = defaultMode
			return nil
		}
		mode = models.CryptoMode(string(v))
		return nil
	})

	return mode, err
}

// SetCryptoMode updates the stored crypto mode
func SetCryptoMode(mode models.CryptoMode) error {
	if mode != models.ClassicalMode && mode != models.QuantumSafeMode {
		return errors.New("invalid crypto mode")
	}
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(settingsBucket))
		return b.Put([]byte(modeKey), []byte(mode))
	})
}
