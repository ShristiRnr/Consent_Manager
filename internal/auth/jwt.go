package auth

import (
	"consultrnr/consent-manager/internal/models"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type DataPrincipalClaims struct {
	PrincipalID string `json:"principalId"`
	TenantID    string `json:"tenantId"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	TokenType   string `json:"typ"`
	jwt.RegisteredClaims
}

type FiduciaryClaims struct {
	FiduciaryID string `json:"fiduciaryId"`
	TenantID    string `json:"tenantId"`
	Role        string `json:"role"`
	Type        string `json:"typ"`
	jwt.RegisteredClaims
}

func (c *DataPrincipalClaims) Valid() error {
	return c.RegisteredClaims.Valid()
}

func (c *FiduciaryClaims) Validate(ctx context.Context) error {
	return c.RegisteredClaims.Valid()
}

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
	claims := &DataPrincipalClaims{
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
	claims := &DataPrincipalClaims{
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
	claims := &FiduciaryClaims{
		FiduciaryID: user.ID.String(),
		TenantID:    user.TenantID.String(),
		Role:        user.Role,
		Type:        "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateFiduciaryRefreshToken(user models.FiduciaryUser, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	claims := &FiduciaryClaims{
		FiduciaryID: user.ID.String(),
		TenantID:    user.TenantID.String(),
		Role:        user.Role,
		Type:        "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// ========== Token Parsers ==========

func ParseFiduciaryToken(tokenStr string, publicKey *rsa.PublicKey) (*FiduciaryClaims, error) {
	return parseFiduciaryTokenTyped(tokenStr, publicKey, "access")
}

func ParseFiduciaryRefreshToken(tokenStr string, publicKey *rsa.PublicKey) (*FiduciaryClaims, error) {
	return parseFiduciaryTokenTyped(tokenStr, publicKey, "refresh")
}

func parseFiduciaryTokenTyped(tokenStr string, publicKey *rsa.PublicKey, wantType string) (*FiduciaryClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &FiduciaryClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*FiduciaryClaims)
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

func ParseDataPrincipalToken(tokenStr string, publicKey *rsa.PublicKey) (*DataPrincipalClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &DataPrincipalClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*DataPrincipalClaims)
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

func ParseDataPrincipalRefreshToken(tokenStr string, publicKey *rsa.PublicKey) (*DataPrincipalClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &DataPrincipalClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*DataPrincipalClaims)
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
