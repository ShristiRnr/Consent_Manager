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

type UserClaims struct {
	UserID    string            `json:"userId"`
	User      models.MasterUser `json:"user"`
	Email     string            `json:"email"`
	Phone     string            `json:"phone"`
	Tenants   []string          `json:"tenants"`
	TokenType string            `json:"typ"`
	jwt.RegisteredClaims
}

type AdminClaims struct {
	AdminID   string `json:"adminId"`
	TenantID  string `json:"tenantId"`
	Role      string `json:"role"`
	TokenType string `json:"typ"`
	jwt.RegisteredClaims
}

func (uc *UserClaims) Valid() error {
	return uc.RegisteredClaims.Valid()
}

func (c *AdminClaims) Validate(ctx context.Context) error {
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

// Includes full user struct so permissions & role are inside JWT
func GenerateUserToken(user models.MasterUser, tenants []string, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	claims := &UserClaims{
		UserID:    user.UserID.String(),
		Email:     user.Email,
		Phone:     user.Phone,
		Tenants:   tenants,
		TokenType: "access",
		User:      user,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateUserRefreshToken(user models.MasterUser, tenants []string, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	claims := &UserClaims{
		UserID:    user.UserID.String(),
		Email:     user.Email,
		Phone:     user.Phone,
		Tenants:   tenants,
		TokenType: "refresh",
		User:      user,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateAdminToken(adminID, tenantID, role string, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	claims := &AdminClaims{
		AdminID:   adminID,
		TenantID:  tenantID,
		Role:      role,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateAdminRefreshToken(adminID, tenantID, role string, privateKey *rsa.PrivateKey, ttl time.Duration) (string, error) {
	claims := &AdminClaims{
		AdminID:   adminID,
		TenantID:  tenantID,
		Role:      role,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// ========== Token Parsers ==========

func ParseAdminToken(tokenStr string, publicKey *rsa.PublicKey) (*AdminClaims, error) {
	return parseAdminTokenTyped(tokenStr, publicKey, "access")
}

func ParseAdminRefreshToken(tokenStr string, publicKey *rsa.PublicKey) (*AdminClaims, error) {
	return parseAdminTokenTyped(tokenStr, publicKey, "refresh")
}

func parseAdminTokenTyped(tokenStr string, publicKey *rsa.PublicKey, wantType string) (*AdminClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AdminClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AdminClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return nil, jwt.ErrTokenExpired
	}
	if claims.TokenType != wantType {
		return nil, errors.New("token type mismatch")
	}
	return claims, nil
}

func ParseUserToken(tokenStr string, publicKey *rsa.PublicKey) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*UserClaims)
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

func ParseUserRefreshToken(tokenStr string, publicKey *rsa.PublicKey) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*UserClaims)
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
