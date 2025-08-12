// middlewares/jwt_auth.go
package middlewares

import (
	jwtAuth "consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"context"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// Define a custom type for tenant context key to avoid SA1029 warning
type tenantIDKeyType struct{}

var tenantIDKey tenantIDKeyType

func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header required")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

// JWTFiduciaryAuthMiddleware validates the JWT and injects FiduciaryClaims into request.Context.
func JWTFiduciaryAuthMiddleware(pubKey *rsa.PublicKey) func(http.Handler) http.Handler {
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

			if claims.FiduciaryID == "" || claims.TenantID == "" || claims.Role == "" {
				http.Error(w, "missing essential claims", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), contextkeys.FiduciaryClaimsKey, claims)
			ctx = context.WithValue(ctx, tenantIDKey, claims.TenantID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func JWTDataPrincipalAuthMiddleware(pubKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			claims := &jwtAuth.DataPrincipalClaims{}
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

			if claims.PrincipalID == "" {
				http.Error(w, "missing essential claims", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), contextkeys.UserClaimsKey, claims)
			if claims.TenantID != "" {
				ctx = context.WithValue(ctx, tenantIDKey, claims.TenantID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAuthClaims retrieves the DataPrincipalClaims previously set in context.
func GetAuthClaims(r *http.Request) *jwtAuth.DataPrincipalClaims {
	v := r.Context().Value(contextkeys.UserClaimsKey)
	if v != nil {
		if ac, ok := v.(*jwtAuth.DataPrincipalClaims); ok {
			return ac
		}
	}
	log.Printf("[JWT DEBUG] GetAuthClaims: %T", v)
	return nil
}

// GetClaimsFromContext retrieves the DataPrincipalClaims from the request context.
func GetClaimsFromContext(ctx context.Context) *jwtAuth.DataPrincipalClaims {
	if v := ctx.Value(contextkeys.UserClaimsKey); v != nil {
		if ac, ok := v.(*jwtAuth.DataPrincipalClaims); ok {
			return ac
		}
	}
	return nil
}

func GetFiduciaryAuthClaims(ctx context.Context) *jwtAuth.FiduciaryClaims {
	v := ctx.Value(contextkeys.FiduciaryClaimsKey)
	if v != nil {
		if ac, ok := v.(*jwtAuth.FiduciaryClaims); ok {
			return ac
		}
	}
	log.Printf("[JWT DEBUG] Fiduciary claims not found in context")
	return nil
}

// RequireRoles rejects requests unless the user’s role is in allowedRoles.
func RequireRoles(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			claims := GetFiduciaryAuthClaims(r.Context())
			log.Printf("[JWT DEBUG] RequireRoles: got claims from context: %+v", claims)

			if claims == nil {
				http.Error(w, "unauthorized: no claims", http.StatusUnauthorized)
				return
			}
			for _, role := range allowedRoles {
				if claims.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "forbidden: insufficient role", http.StatusForbidden)
		})
	}
}

// helpers to parse PEM keys
func GetPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	pubBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(pubBytes)
}

func GetPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	privBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPrivateKeyFromPEM(privBytes)
}
