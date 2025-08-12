package handlers

import (
	"crypto/rsa"
	"strings"
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func GetPurposesByIDs(ctx context.Context, purposeIDs []uuid.UUID, r *http.Request) ([]models.Purpose, error) {
	tenantDB, _, err := getAdminTenantDBForRequest(r)
	if err != nil {
		return nil, err
	}

	var purposes []models.Purpose
	if err := tenantDB.Where("id IN ?", purposeIDs).Find(&purposes).Error; err != nil {
		return nil, err
	}
	return purposes, nil
}

func getAdminTenantDBForRequest(r *http.Request) (*gorm.DB, string, error) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		return nil, "", errors.New("missing fiduciary claims")
	}

	tenantID := claims.TenantID
	if tenantID == "" {
		return nil, "", errors.New("missing tenant id from claims")
	}

	tenantSchema := "tenant_" + tenantID[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get tenant db: %w", err)
	}
	return tenantDB, tenantID, nil
}

// helpers.go or in the handler file
func getFiduciaryClaims(r *http.Request, publicKey *rsa.PublicKey) (*auth.FiduciaryClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("authorization header required")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, errors.New("invalid authorization header format")
	}

	tokenString := parts[1]
	claims, err := auth.ParseFiduciaryToken(tokenString, publicKey)
	if err != nil {
		return nil, errors.New("invalid or expired token")
	}

	return claims, nil
}

func getTenantDBForRequest(r *http.Request) (*gorm.DB, string, error) {
	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		return nil, "", errors.New("missing data principal claims")
	}

	tenantID := claims.TenantID
	if tenantID == "" {
		return nil, "", errors.New("missing tenant id from claims")
	}

	tenantSchema := "tenant_" + tenantID[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get tenant db: %w", err)
	}
	return tenantDB, tenantID, nil
}
