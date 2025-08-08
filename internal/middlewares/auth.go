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

// extractBearerToken extracts the token from the Authorization header
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid Authorization header format")
	}
	return parts[1], nil
}

// RequireAdminAuth verifies JWT for admin endpoints
func RequireAdminAuth(publicKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
				return
			}
			claims, err := auth.ParseAdminToken(tokenStr, publicKey)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}
			ctx := context.WithValue(r.Context(), contextkeys.AdminClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireUserAuth verifies JWT for user endpoints
func RequireUserAuth(publicKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
				return
			}
			claims, err := auth.ParseUserToken(tokenStr, publicKey)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "Invalid or expired token")
				return
			}
			ctx := context.WithValue(r.Context(), contextkeys.UserClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission enforces role/module-specific permissions
func RequirePermission(module string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// First check admin claims
			if v := r.Context().Value(contextkeys.AdminClaimsKey); v != nil {
				if ac, ok := v.(*auth.AdminClaims); ok {
					if ac.Role == "superadmin" {
						// SuperAdmin has full access
						next.ServeHTTP(w, r)
						return
					}
					if ac.Role == "admin" && module == "usermanagement" {
						writeAuthError(w, http.StatusForbidden, "Admins cannot access user management")
						return
					}
					next.ServeHTTP(w, r)
					return
				}
			}

			// Then check user claims
			if v := r.Context().Value(contextkeys.UserClaimsKey); v != nil {
				if uc, ok := v.(*auth.UserClaims); ok {
					switch uc.User.Role { 
					case "dpo":
						switch module {
						case "consent":
							if !uc.User.CanManageConsent { 
								writeAuthError(w, http.StatusForbidden, "Not allowed to manage consent")
								return
							}
						case "grievance":
							if !uc.User.CanManageGrievance {
								writeAuthError(w, http.StatusForbidden, "Not allowed to manage grievance")
								return
							}
						case "purposes":
							if !uc.User.CanManagePurposes {
								writeAuthError(w, http.StatusForbidden, "Not allowed to manage purposes")
								return
							}
						case "auditlogs":
							if !uc.User.CanManageAuditLogs {
								writeAuthError(w, http.StatusForbidden, "Not allowed to manage audit logs")
								return
							}
						}
					case "developer":
						if module == "purposes" && r.Method != http.MethodGet {
							writeAuthError(w, http.StatusForbidden, "Developers have read-only access to purposes")
							return
						}
					case "viewer":
						if r.Method != http.MethodGet {
							writeAuthError(w, http.StatusForbidden, "Viewers have read-only access")
							return
						}
					}
					next.ServeHTTP(w, r)
					return
				}
			}

			writeAuthError(w, http.StatusUnauthorized, "Unauthorized")
		})
	}
}

// GetUserID extracts the user ID from context claims
func GetUserID(ctx context.Context) string {
	if v := ctx.Value(contextkeys.UserClaimsKey); v != nil {
		if uc, ok := v.(*auth.UserClaims); ok {
			return uc.UserID
		}
	}
	return ""
}

// GetUserData fetches the full MasterUser record from DB
func GetUserData(db *gorm.DB, ctx context.Context) (models.MasterUser, error) {
	claims, ok := ctx.Value(contextkeys.UserClaimsKey).(*auth.UserClaims)
	if !ok || claims == nil {
		return models.MasterUser{}, errors.New("no claims in context")
	}
	var user models.MasterUser
	if err := db.Where("user_id = ?", claims.UserID).First(&user).Error; err != nil {
		return models.MasterUser{}, err
	}
	return user, nil
}

// GetAdminID extracts the admin ID from context claims
func GetAdminID(ctx context.Context) string {
	if v := ctx.Value(contextkeys.AdminClaimsKey); v != nil {
		if ac, ok := v.(*auth.AdminClaims); ok {
			return ac.AdminID
		}
		
	}
	return ""
}
