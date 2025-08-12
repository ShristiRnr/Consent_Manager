package middlewares

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"

	jwtAuth "consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"

	"github.com/golang-jwt/jwt/v4"
)

// APIAuthMiddleware validates the JWT access token for public API clients.
func APIAuthMiddleware(pubKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			claims := &jwtAuth.FiduciaryClaims{}
			token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return pubKey, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			// Check for API-specific claims
			if claims.Type != "api" || claims.Subject == "" { // Subject holds the ClientID
				http.Error(w, "invalid API token claims", http.StatusUnauthorized)
				return
			}

			// Inject claims into context
			ctx := context.WithValue(r.Context(), contextkeys.FiduciaryClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
