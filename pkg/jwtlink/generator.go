package jwtlink

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secret []byte

// Init sets the signing secret for the JWT operations.
func Init(secretStr string) {
	secret = []byte(secretStr)
}

type ReviewClaims struct {
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
	jwt.RegisteredClaims
}

// GenerateReviewToken creates a signed JWT with tenant/user context and expiration.
func GenerateReviewToken(tenantID, userID string, ttl time.Duration) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("JWT secret not initialized")
	}
	claims := ReviewClaims{
		TenantID: tenantID,
		UserID:   userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "consent-manager",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// ParseReviewToken validates and parses the JWT into ReviewClaims.
func ParseReviewToken(tokenStr string) (*ReviewClaims, error) {
	if len(secret) == 0 {
		return nil, errors.New("JWT secret not initialized")
	}
	token, err := jwt.ParseWithClaims(tokenStr, &ReviewClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token parse error: %w", err)
	}

	claims, ok := token.Claims.(*ReviewClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid or expired token claims")
	}

	return claims, nil
}
