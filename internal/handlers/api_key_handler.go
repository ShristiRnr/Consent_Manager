package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/encryption"
)

type CreateAPIKeyRequest struct {
	Label          string   `json:"label"`
	Scopes         []string `json:"scopes"`
	ExpiresAt      *string  `json:"expiresAt,omitempty"` // ISO string
	WhitelistedIPs []string `json:"whitelistedIPs,omitempty"`
}

type CreateAPIKeyResponse struct {
	KeyID  uuid.UUID `json:"keyId"`
	Label  string    `json:"label"`
	APIKey string    `json:"apiKey"`
}

func parseBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", http.ErrNoCookie
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", http.ErrNoCookie
	}
	return parts[1], nil
}

func CreateAPIKeyHandler(db *gorm.DB, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := parseBearerToken(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := auth.ParseFiduciaryToken(tokenStr, publicKey)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		var req CreateAPIKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Label == "" {
			http.Error(w, "label is required", http.StatusBadRequest)
			return
		}

		// Generate random API key (32 bytes → hex string)
		rawKey := make([]byte, 32)
		if _, err := rand.Read(rawKey); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		apiKey := hex.EncodeToString(rawKey)

		// Encrypt API key for DB storage
		encryptedKey, err := encryption.DeterministicEncrypt(apiKey)
		if err != nil {
			http.Error(w, "internal error (encryption failed)", http.StatusInternalServerError)
			return
		}

		// Marshal scopes/ips for DB
		scopesBytes, _ := json.Marshal(req.Scopes)
		ipsBytes, _ := json.Marshal(req.WhitelistedIPs)

		var expiresAt *time.Time
		if req.ExpiresAt != nil && *req.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err == nil {
				expiresAt = &t
			}
		}

		key := models.APIKey{
			KeyID:          uuid.New(),
			TenantID:       uuid.MustParse(claims.TenantID),
			UserID:         uuid.MustParse(claims.ID),
			Label:          req.Label,
			HashedKey:      encryptedKey,
			Scopes:         scopesBytes,
			CreatedAt:      time.Now(),
			Revoked:        false,
			ExpiresAt:      expiresAt,
			WhitelistedIPs: ipsBytes,
		}
		if err := db.Create(&key).Error; err != nil {
			http.Error(w, "could not store key", http.StatusInternalServerError)
			return
		}

		resp := CreateAPIKeyResponse{
			KeyID:  key.KeyID,
			Label:  key.Label,
			APIKey: apiKey, // Only returned at creation
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func ListAPIKeysHandler(db *gorm.DB, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := parseBearerToken(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := auth.ParseFiduciaryToken(tokenStr, publicKey)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		var keys []models.APIKey
		if err := db.Where("tenant_id = ? AND revoked = false", claims.TenantID).Find(&keys).Error; err != nil {
			http.Error(w, "could not fetch keys", http.StatusInternalServerError)
			return
		}

		type OutKey struct {
			KeyID          uuid.UUID  `json:"keyId"`
			Label          string     `json:"label"`
			CreatedAt      time.Time  `json:"createdAt"`
			LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
			Revoked        bool       `json:"revoked"`
			RevokedAt      *time.Time `json:"revokedAt,omitempty"`
			ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
			Scopes         []string   `json:"scopes"`
			WhitelistedIPs []string   `json:"whitelistedIps"`
		}

		var outKeys []OutKey
		for _, key := range keys {
			// Ensure scopes is never null!
			var scopes []string
			if len(key.Scopes) > 0 {
				_ = json.Unmarshal(key.Scopes, &scopes)
			}
			if scopes == nil {
				scopes = []string{}
			}
			// IPs
			var whitelisted []string
			if len(key.WhitelistedIPs) > 0 {
				_ = json.Unmarshal(key.WhitelistedIPs, &whitelisted)
			}
			if whitelisted == nil {
				whitelisted = []string{}
			}
			outKeys = append(outKeys, OutKey{
				KeyID:          key.KeyID,
				Label:          key.Label,
				CreatedAt:      key.CreatedAt,
				LastUsedAt:     key.LastUsedAt,
				Revoked:        key.Revoked,
				RevokedAt:      key.RevokedAt,
				ExpiresAt:      key.ExpiresAt,
				Scopes:         scopes,
				WhitelistedIPs: whitelisted,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": outKeys,
		})
	}
}

func RevokeAPIKeyHandler(db *gorm.DB, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := parseBearerToken(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := auth.ParseFiduciaryToken(tokenStr, publicKey)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		keyID := r.URL.Query().Get("id")
		if keyID == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if err := db.Model(&models.APIKey{}).
			Where("key_id = ? AND tenant_id = ?", keyID, claims.TenantID).
			Update("revoked", true).Error; err != nil {
			http.Error(w, "could not revoke", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func ReviewTokenHandler(db *gorm.DB, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := parseBearerToken(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := auth.ParseFiduciaryToken(tokenStr, publicKey)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(claims)
	}
}
