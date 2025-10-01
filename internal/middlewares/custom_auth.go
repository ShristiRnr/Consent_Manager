package middlewares

import (
	"consultrnr/consent-manager/internal/claims"
	"consultrnr/consent-manager/internal/contextkeys"
	"net/http"
)

// AllowAdminAccess is a middleware that allows access if the user has admin role
// or any of the specified permissions
func AllowAdminAccess(requiredPermissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
			if !ok || claims == nil {
				writeAuthError(w, http.StatusUnauthorized, "Unauthorized: no claims found")
				return
			}

			// If the user has the admin role, allow access
			if claims.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			// Otherwise, check for specific permissions
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
