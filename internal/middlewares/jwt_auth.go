// middlewares/jwt_auth.go
package middlewares

import (
	jwtAuth "consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/models"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

// Define a custom type for tenant context key to avoid SA1029 warning
type tenantIDKeyType struct{}

var tenantIDKey tenantIDKeyType

// JWTAuthMiddleware validates the JWT and injects AdminClaims into request.Context.
func JWTAuthMiddleware(pubKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			claims := GetAdminAuthClaims(r.Context())
			if claims == nil {
				// Parse the token with claims
				claims = &jwtAuth.AdminClaims{}
			}
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

			// You can add more validation here if needed
			if claims.AdminID == "" || claims.TenantID == "" || claims.Role == "" {
				http.Error(w, "missing essential claims", http.StatusUnauthorized)
				return
			}

			// Add to context with custom key types
			ctx := context.WithValue(r.Context(), contextkeys.AdminClaimsKey, claims)
			ctx = context.WithValue(ctx, tenantIDKey, claims.TenantID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func JWTUserAuthMiddleware(pubKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearerToken(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return pubKey, nil
			})
			if err != nil || !token.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			claimsMap, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "invalid claims", http.StatusUnauthorized)
				return
			}

			// Extract values
			userID := fmt.Sprintf("%v", claimsMap["userId"])
			email := fmt.Sprintf("%v", claimsMap["email"])
			phone := fmt.Sprintf("%v", claimsMap["phone"])
			tokenType := fmt.Sprintf("%v", claimsMap["typ"])

			// tenants can be missing, null, empty, or an array
			tenantStrs := []string{}
			if tenants, exists := claimsMap["tenants"]; exists && tenants != nil {
				if arr, ok := tenants.([]interface{}); ok {
					for _, t := range arr {
						tenantStrs = append(tenantStrs, fmt.Sprintf("%v", t))
					}
				}
			}

			if userID == "" {
				http.Error(w, "missing essential claims", http.StatusUnauthorized)
				return
			}

			// parse the "user" claim into auth.MasterUser
			var user models.MasterUser
			if m, ok := claimsMap["user"].(map[string]interface{}); ok {
				b, err := json.Marshal(m)
				if err != nil {
					http.Error(w, "invalid user claim", http.StatusUnauthorized)
					return
				}
				if err := json.Unmarshal(b, &user); err != nil {
					http.Error(w, "invalid user claim", http.StatusUnauthorized)
					return
				}
			} else {
				http.Error(w, "invalid user claim", http.StatusUnauthorized)
				return
			}

			uc := &jwtAuth.UserClaims{
				UserID:    userID,
				Email:     email,
				User:      user,
				Phone:     phone,
				Tenants:   tenantStrs,
				TokenType: tokenType,
			}

			ctx := context.WithValue(r.Context(), contextkeys.UserClaimsKey, uc)
			if len(tenantStrs) > 0 {
				ctx = context.WithValue(ctx, tenantIDKey, tenantStrs[0])
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAuthClaims retrieves the AuthClaims previously set in context.
func GetAuthClaims(r *http.Request) *jwtAuth.UserClaims {
	v := r.Context().Value(contextkeys.UserClaimsKey)
	if v != nil {
		if ac, ok := v.(*jwtAuth.UserClaims); ok {
			return ac
		}
	}
	log.Printf("[JWT DEBUG] GetAuthClaims: %T", v)
	return nil
}

// GetClaimsFromContext retrieves the UserClaims from the request context.
func GetClaimsFromContext(ctx context.Context) *jwtAuth.UserClaims {
	if v := ctx.Value(contextkeys.UserClaimsKey); v != nil {
		if ac, ok := v.(*jwtAuth.UserClaims); ok {
			return ac
		}
	}
	return nil
}

func GetAdminAuthClaims(ctx context.Context) *jwtAuth.AdminClaims {
	v := ctx.Value(contextkeys.AdminClaimsKey)
	if v != nil {
		if ac, ok := v.(*jwtAuth.AdminClaims); ok {
			return ac
		}
	}
	log.Printf("[JWT DEBUG] SET PTR: %s TYPE: %T VAL: %v", contextkeys.AdminClaimsKey, contextkeys.AdminClaimsKey, contextkeys.AdminClaimsKey)
	return nil
}

// RequireRoles rejects requests unless the user’s role is in allowedRoles.
func RequireRoles(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			claims := GetAdminAuthClaims(r.Context())
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

