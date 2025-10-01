package middlewares

import (
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/claims"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/models"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"

	"gorm.io/gorm"
)

// FiduciaryClaimsKey is the key used to store fiduciary claims in the context. Exported for testing.
var FiduciaryClaimsKey = contextkeys.FiduciaryClaimsKey

// writeAuthError writes JSON-formatted error responses for auth failures
func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// RequireFiduciaryAuth verifies JWT for fiduciary endpoints
func RequireFiduciaryAuth(publicKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
				return
			}
			claims, err := auth.ParseFiduciaryToken(tokenStr, publicKey)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}
			ctx := context.WithValue(r.Context(), contextkeys.FiduciaryClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireDataPrincipalAuth verifies JWT for data principal endpoints
func RequireDataPrincipalAuth(publicKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
				return
			}
			claims, err := auth.ParseDataPrincipalToken(tokenStr, publicKey)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}
			ctx := context.WithValue(r.Context(), contextkeys.UserClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission checks if the fiduciary user has at least one of the required permissions.
func RequirePermission(requiredPermissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
			if !ok || claims == nil {
				writeAuthError(w, http.StatusUnauthorized, "Unauthorized: no claims found")
				return
			}

			// Check if the user has any of the required permissions
			for _, p := range requiredPermissions {
				if claims.Permissions[p] {
					next.ServeHTTP(w, r)
					return
				}
			}

			writeAuthError(w, http.StatusForbidden, "Forbidden: insufficient permissions")
		})
	}
}

// GetDataPrincipalID extracts the data principal ID from context claims
func GetDataPrincipalID(ctx context.Context) string {
	if v := ctx.Value(contextkeys.UserClaimsKey); v != nil {
		if uc, ok := v.(*claims.DataPrincipalClaims); ok {
			return uc.PrincipalID
		}
	}
	return ""
}

// GetDataPrincipal fetches the full DataPrincipal record from DB
func GetDataPrincipal(db *gorm.DB, ctx context.Context) (*models.DataPrincipal, error) {
	claims, ok := ctx.Value(contextkeys.UserClaimsKey).(*claims.DataPrincipalClaims)
	if !ok || claims == nil {
		return nil, errors.New("no claims in context")
	}
	var user models.DataPrincipal
	if err := db.Where("id = ?", claims.PrincipalID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetFiduciaryID extracts the fiduciary ID from context claims
func GetFiduciaryID(ctx context.Context) string {
	if v := ctx.Value(contextkeys.FiduciaryClaimsKey); v != nil {
		if fc, ok := v.(*claims.FiduciaryClaims); ok {
			return fc.FiduciaryID
		}
	}
	return ""
}
