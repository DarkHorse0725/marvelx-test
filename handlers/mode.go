package handlers

import (
	"encoding/json"
	"net/http"

	"secure-vault/models"
	"secure-vault/storage"
	"secure-vault/utils"
)

type setModeRequest struct {
	Mode string `json:"mode"` // "classical" or "quantum-safe"
}

func SetCryptoModeHandler(w http.ResponseWriter, r *http.Request) {
	var req setModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if !models.IsValidCryptoMode(req.Mode) {
		http.Error(w, "Invalid mode: must be 'classical' or 'quantum-safe'", http.StatusBadRequest)
		return
	}

	currentMode, err := storage.GetCryptoMode()
	if err != nil {
		http.Error(w, "Failed to get current crypto mode", http.StatusInternalServerError)
		return
	}

	mode, err := models.ToCryptoMode(req.Mode)
	if err != nil {
		http.Error(w, "Invalid mode: must be 'classical' or 'quantum-safe'", http.StatusBadRequest)
		return
	}

	// Skip if same mode
	if mode == currentMode {
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Mode unchanged — already in " + req.Mode,
			"mode":    req.Mode,
		})
		return
	}

	// Migrate all stored keys
	if err := storage.ReEncryptAllVaultEntries(mode); err != nil {
		http.Error(w, "Failed to re-encrypt vault keys: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Persist new mode
	if err := storage.SetCryptoMode(mode); err != nil {
		http.Error(w, "Failed to update mode", http.StatusInternalServerError)
		return
	}

	utils.Info("mode", "toggled crypto mode to %s", req.Mode)

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Crypto mode updated and all keys re-encrypted",
		"mode":    req.Mode,
	})
}

func GetCryptoModeHandler(w http.ResponseWriter, r *http.Request) {
	mode, err := storage.GetCryptoMode()
	if err != nil {
		http.Error(w, "Failed to retrieve crypto mode", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"mode": string(mode),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
