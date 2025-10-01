package auth

import (
	"consultrnr/consent-manager/internal/claims"
	"consultrnr/consent-manager/internal/models"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Load private key from PEM
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPrivateKeyFromPEM(b)
}

// Load public key from PEM
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(b)
}

// ========== Token Generators ==========

func GenerateDataPrincipalToken(user models.DataPrincipal, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	claims := &claims.DataPrincipalClaims{
		PrincipalID: user.ID.String(),
		TenantID:    user.TenantID.String(),
		Email:       user.Email,
		Phone:       user.Phone,
		TokenType:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateDataPrincipalRefreshToken(user models.DataPrincipal, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	claims := &claims.DataPrincipalClaims{
		PrincipalID: user.ID.String(),
		TenantID:    user.TenantID.String(),
		Email:       user.Email,
		Phone:       user.Phone,
		TokenType:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateFiduciaryToken(user models.FiduciaryUser, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	roleNames := []string{}
	permissions := make(map[string]bool)
	for _, role := range user.Roles {
		roleNames = append(roleNames, role.Name)
		for _, p := range role.Permissions {
			permissions[p.Name] = true
		}
	}
	claims := &claims.FiduciaryClaims{
		FiduciaryID: user.ID.String(),
		TenantID:    user.TenantID.String(),
		Roles:       roleNames,
		Permissions: permissions,
		Type:        "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateFiduciaryImpersonationToken(impersonatedUser models.FiduciaryUser, impersonatorID string, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	roleNames := []string{}
	permissions := make(map[string]bool)
	for _, role := range impersonatedUser.Roles {
		roleNames = append(roleNames, role.Name)
		for _, p := range role.Permissions {
			permissions[p.Name] = true
		}
	}

	claims := &claims.FiduciaryClaims{
		FiduciaryID:    impersonatedUser.ID.String(),
		TenantID:       impersonatedUser.TenantID.String(),
		Roles:          roleNames,
		Permissions:    permissions,
		ImpersonatorID: impersonatorID, // Set the ID of the admin doing the impersonating
		Type:           "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateFiduciaryRefreshToken(user models.FiduciaryUser, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	roleNames := []string{}
	for _, role := range user.Roles {
		roleNames = append(roleNames, role.Name)
	}

	claims := &claims.FiduciaryClaims{
		FiduciaryID: user.ID.String(),
		TenantID:    user.TenantID.String(),
		// Refresh tokens typically don't need full permissions, just roles for context
		Roles: roleNames,
		// Keep deprecated role for now if any old logic depends on it during refresh
		Role: user.Role,
		Type: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// ========== Token Parsers ==========

func ParseFiduciaryToken(tokenStr string, publicKey *rsa.PublicKey) (*claims.FiduciaryClaims, error) {
	return parseFiduciaryTokenTyped(tokenStr, publicKey, "access")
}

func ParseFiduciaryRefreshToken(tokenStr string, publicKey *rsa.PublicKey) (*claims.FiduciaryClaims, error) {
	return parseFiduciaryTokenTyped(tokenStr, publicKey, "refresh")
}

func parseFiduciaryTokenTyped(tokenStr string, publicKey *rsa.PublicKey, wantType string) (*claims.FiduciaryClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &claims.FiduciaryClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*claims.FiduciaryClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return nil, jwt.ErrTokenExpired
	}
	if claims.Type != wantType {
		return nil, errors.New("token type mismatch")
	}
	return claims, nil
}

func ParseDataPrincipalToken(tokenStr string, publicKey *rsa.PublicKey) (*claims.DataPrincipalClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &claims.DataPrincipalClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*claims.DataPrincipalClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return nil, jwt.ErrTokenExpired
	}
	if claims.TokenType != "access" {
		return nil, errors.New("token is not an access token")
	}
	return claims, nil
}

func ParseDataPrincipalRefreshToken(tokenStr string, publicKey *rsa.PublicKey) (*claims.DataPrincipalClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &claims.DataPrincipalClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*claims.DataPrincipalClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return nil, jwt.ErrTokenExpired
	}
	if claims.TokenType != "refresh" {
		return nil, errors.New("token is not a refresh token")
	}
	return claims, nil
}
