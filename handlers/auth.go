package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"secure-vault/utils"

	"github.com/golang-jwt/jwt/v5"
)

type AuthRequest struct {
	UserID string `json:"user_id"`
}

func GetToken(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// // Fake auth check (in production use real user DB)
	// if req.Secret != "password" {
	// 	utils.Warn("auth", "Invalid credentials for user: %s", req.UserID)
	// 	http.Error(w, "unauthorized", http.StatusUnauthorized)
	// 	return
	// }

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		http.Error(w, "JWT_SECRET not set", http.StatusInternalServerError)
		return
	}

	// Create the token
	claims := jwt.MapClaims{
		"sub": req.UserID,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		utils.Error("auth", "Failed to sign token: %v", err)
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	utils.Info("auth", "Issued token for user: %s", req.UserID)
	json.NewEncoder(w).Encode(map[string]string{"token": signed})
}
