package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	jwt "consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/log"

	"github.com/google/uuid"
)

type IdentifyRequest struct {
	UserID string `json:"userId"`
}

func identifyUserHandler(w http.ResponseWriter, r *http.Request) {
	// 1) Auth header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "missing Authorization header", http.StatusUnauthorized)
		return
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		http.Error(w, "invalid Authorization header", http.StatusUnauthorized)
		return
	}

	publicKey, err := jwt.LoadPublicKey("path/to/public_key.pem")
	if err != nil {
		http.Error(w, "failed to load public key", http.StatusInternalServerError)
		return
	}

	// 2) Parse token and require admin
	claims, err := jwt.ParseAdminToken(parts[1], publicKey)
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}
	if claims == nil {
		http.Error(w, "forbidden: admin only", http.StatusForbidden)
		return
	}

	// 3) Decode JSON body
	var req IdentifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// 4) Parse UUID
	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		http.Error(w, "invalid userId format", http.StatusBadRequest)
		return
	}

	// 5) Lookup user in master DB
	masterDB := db.GetMasterDB()
	var mu models.MasterUser
	if err := masterDB.
		Where("user_id = ?", userUUID).
		First(&mu).
		Error; err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	log.Logger.Info().
		Str("admin", claims.Subject).
		Str("user_id", mu.UserID.String()).
		Msg("Master user lookup")

	// 6) Return JSON with email
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"userId": mu.UserID.String(),
		"email":  mu.Email,
	})
}
