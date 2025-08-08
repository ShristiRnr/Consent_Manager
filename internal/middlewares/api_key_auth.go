package middlewares

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	contextKey "consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/encryption"

	"gorm.io/gorm"
)

const APIKeyHeader = "X-API-Key"

type APIKeyClaims struct {
	TenantID string
	Scopes   []string
}

var apiKeyClaimsContextKey = contextKey.APIKeyClaimsKey

// APIKeyAuthMiddleware returns a net/http middleware
func APIKeyAuthMiddleware(db *gorm.DB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get(APIKeyHeader)
			if raw == "" {
				http.Error(w, "Missing API key", http.StatusUnauthorized)
				return
			}

			// Lookup via deterministic hash
			hashedKey, err := encryption.DeterministicEncrypt(raw)
			if err != nil {
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}

			var key models.APIKey
			if err := db.Where("hashed_key = ? AND revoked = false", hashedKey).First(&key).Error; err != nil {
				http.Error(w, "Invalid or revoked API key", http.StatusUnauthorized)
				return
			}

			// Check if the key is active
			if key.Revoked {
				http.Error(w, "API key revoked", http.StatusUnauthorized)
				return
			}

			//check hashedKey matches the raw key
			if hashedKey != key.HashedKey {
				log.Printf("API key mismatch: %s != %s", hashedKey, key.HashedKey)
				http.Error(w, "Invalid API key", http.StatusUnauthorized)
				return
			}

			// Check expiry
			now := time.Now()
			if key.ExpiresAt != nil && now.After(*key.ExpiresAt) {
				http.Error(w, "API key expired", http.StatusUnauthorized)
				return
			}

			// Check IP whitelist Review Algo
			// clientIP := getClientIP(r)
			// if !isIPAllowed(clientIP, key.WhitelistedIPs) {
			// 	log.Print("number of whitelisted IPs: ", len(key.WhitelistedIPs))
			// 	if len(key.WhitelistedIPs) == 0 {
			// 		log.Printf("API key %s has no IP whitelist, allowing all IPs", key.KeyID)
			// 	} else {
			// 		log.Printf("IP %s not allowed for API key %s", clientIP, key.KeyID)
			// 		http.Error(w, "IP not allowed", http.StatusForbidden)
			// 		return
			// 	}
			// }

			// Update last used timestamp (best effort, non-blocking)
			_ = db.Model(&models.APIKey{}).
				Where("key_id = ?", key.KeyID).
				Update("last_used_at", now)

			// Decode scopes
			var scopes []string
			if err := json.Unmarshal(key.Scopes, &scopes); err != nil {
				http.Error(w, "Failed to parse API key scopes", http.StatusInternalServerError)
				return
			}

			claims := &APIKeyClaims{
				TenantID: key.TenantID.String(),
				Scopes:   scopes,
			}

			// Attach to context
			ctx := context.WithValue(r.Context(), apiKeyClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}


// HasScope checks if the request’s APIKeyClaims contain a given scope
func HasScope(r *http.Request, scope string) bool {
	if claims := GetAPIKeyClaims(r); claims != nil {
		for _, s := range claims.Scopes {
			if s == scope {
				return true
			}
		}
	}
	return false
}

// GetAPIKeyClaims retrieves the APIKeyClaims from the request context
func GetAPIKeyClaims(r *http.Request) *APIKeyClaims {
	if v := r.Context().Value(apiKeyClaimsContextKey); v != nil {
		if c, ok := v.(*APIKeyClaims); ok {
			return c
		}
	}
	return nil
}
