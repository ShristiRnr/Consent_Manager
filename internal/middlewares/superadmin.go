package middlewares

import (
	"consultrnr/consent-manager/internal/claims"
	contextKey "consultrnr/consent-manager/internal/contextkeys"
	"net/http"
)

// RequireSuperAdmin blocks any admin who is not a superadmin.
func RequireSuperAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextKey.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
		if !ok || claims == nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		if claims.Role != "superadmin" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden - superadmin only"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
