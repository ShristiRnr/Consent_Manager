package middlewares

import (
	"consultrnr/consent-manager/internal/models"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"gorm.io/gorm"
)

func DynamicCORSMiddleware(db *gorm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			apiKey := r.Header.Get("X-API-Key")

			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			if r.Method == http.MethodOptions {
				// For preflight, just reflect back origin for all known clients
				// (Optional: optimize by checking against all tenant configs if possible)
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Tenant-ID")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// For non-OPTIONS: require valid API key
			if apiKey == "" {
				http.Error(w, "CORS denied: Missing API key", http.StatusForbidden)
				return
			}

			var key models.APIKey
			if err := db.Where("hashed_key = ?", HashAPIKey(apiKey)).First(&key).Error; err != nil {
				http.Error(w, "CORS denied: Invalid API key", http.StatusForbidden)
				return
			}
			var tenant models.Tenant
			if err := db.Where("tenant_id = ?", key.TenantID).First(&tenant).Error; err != nil {
				http.Error(w, "CORS denied: Tenant not found", http.StatusForbidden)
				return
			}
			var cfg struct {
				AllowedCallbacks []string `json:"allowed_callbacks"`
			}
			_ = json.Unmarshal(tenant.Config, &cfg)
			allowed := false
			for _, o := range cfg.AllowedCallbacks {
				if o == "*" || strings.HasPrefix(origin, o) {
					allowed = true
					break
				}
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Tenant-ID")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "CORS denied: Origin not allowed", http.StatusForbidden)
			}
		})
	}
}

// Helper to hash the API key as per your DB storage logic
func HashAPIKey(apiKey string) string {
	// import crypto/sha256, encoding/hex
	h := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(h[:])
}
