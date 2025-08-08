package handlers

import (
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/log"
	"context"
	"errors"
	"net/http"
	"strings"

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
	// This function is similar to getTenantDBForRequest but for admin requests
	token := r.Header.Get("authorization")
	if token == "" {
		return nil, "", errors.New("missing authorization header")
	}
	parts := strings.Split(token, " ")
	if len(parts) != 2 {
		return nil, "", errors.New("invalid authorization header format")
	}
	token = parts[1]
	publicKey, err := auth.LoadPublicKey("public.pem")
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to load public key")
	}
	parsedToken, err := auth.ParseAdminToken(token, publicKey) // Use your public key here if needed
	if err != nil {
		return nil, "", err
	}
	adminID := parsedToken.AdminID
	if adminID == "" {
		return nil, "", errors.New("missing admin id - not authenticated")
	}
	tenantID := parsedToken.TenantID
	if tenantID == "" {
		return nil, "", errors.New("missing tenant id - not authenticated")
	}
	tenantSchema := "tenant_" + tenantID[:8]
	tenantDB, _ := db.GetTenantDB(tenantSchema)
	return tenantDB, tenantID, nil
}

// helpers.go or in the handler file
func getTenantDBForRequest(r *http.Request) (*gorm.DB, string, error) {
	token := r.Header.Get("authorization")
	if token == "" {
		return nil, "", errors.New("missing authorization header")
	}
	parts := strings.Split(token, " ")
	if len(parts) != 2 {
		return nil, "", errors.New("invalid authorization header format")
	}
	token = parts[1]
	publicKey, err := auth.LoadPublicKey("public.pem")
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to load public key")
	}
	parsedToken, err := auth.ParseUserToken(token, publicKey) // Use your public key here if needed
	if err != nil {
		return nil, "", err
	}
	userID := parsedToken.UserID
	if userID == "" {
		return nil, "", errors.New("missing user id - not authenticated")
	}
	//find tenantID from UserTenantLink
	var userTenantLink models.UserTenantLink
	if err := db.MasterDB.Where("user_id = ?", userID).First(&userTenantLink).Error; err != nil {
		return nil, "", err
	}
	tenantID := userTenantLink.TenantID.String()
	if tenantID == "" {
		return nil, "", errors.New("missing tenant id - not authenticated")
	}
	tenantSchema := "tenant_" + tenantID[:8]
	tenantDB, _ := db.GetTenantDB(tenantSchema)
	return tenantDB, tenantID, nil
}

