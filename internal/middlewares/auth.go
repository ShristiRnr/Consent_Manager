package middlewares

import (
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/models"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"gorm.io/gorm"
)

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

// RequirePermission enforces role-based permissions for fiduciaries
func RequirePermission(module string, requiredRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*auth.FiduciaryClaims)
			if !ok || claims == nil {
				writeAuthError(w, http.StatusUnauthorized, "Unauthorized: no claims found")
				return
			}

			// Superadmin has all permissions
			if strings.EqualFold(claims.Role, "superadmin") {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the user's role is in the required list
			for _, role := range requiredRoles {
				if strings.EqualFold(claims.Role, role) {
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
		if uc, ok := v.(*auth.DataPrincipalClaims); ok {
			return uc.PrincipalID
		}
	}
	return ""
}

// GetDataPrincipal fetches the full DataPrincipal record from DB
func GetDataPrincipal(db *gorm.DB, ctx context.Context) (*models.DataPrincipal, error) {
	claims, ok := ctx.Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
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
		if fc, ok := v.(*auth.FiduciaryClaims); ok {
			return fc.FiduciaryID
		}
	}
	return ""
}
