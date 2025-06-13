package storage

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"secure-vault/models"

	"go.etcd.io/bbolt"
)

const vaultBucket = "vault"

var db *bbolt.DB

func Init() error {
	var err error
	dbPath := os.Getenv("VAULT_DB")
	if dbPath == "" {
		dbPath = "vault.db"
	}
	db, err = bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return err
	}

	return db.Update(func(tx *bbolt.Tx) error {
		// Ensure buckets exist
		buckets := []string{"vault", "settings"}
		for _, b := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				return errors.New("init failed: cannot create bucket " + b)
			}
		}

		// Initialize default crypto mode if not set
		settings := tx.Bucket([]byte("settings"))
		if settings.Get([]byte("cryptomode")) == nil {
			err := settings.Put([]byte("cryptomode"), []byte(models.ClassicalMode))
			if err != nil {
				return errors.New("init failed: cannot write default cryptomode")
			}
		}

		return nil
	})
}


// SaveKey stores a VaultEntry (new or updated)
func SaveKey(entry models.VaultEntry) error {
	entry.CreatedAt = time.Now()

	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(vaultBucket))
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(entry.ID), data)
	})
}

// GetKey retrieves a VaultEntry by ID
func GetKey(id string) (models.VaultEntry, error) {
	var entry models.VaultEntry

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(vaultBucket))
		data := b.Get([]byte(id))
		if data == nil {
			return errors.New("key not found")
		}
		return json.Unmarshal(data, &entry)
	})

	return entry, err
}

func UpdateVaultEntry(id string, entry *models.VaultEntry) error {
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(vaultBucket))
		if b == nil {
			return errors.New("vault bucket not found")
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), data)
	})
}
