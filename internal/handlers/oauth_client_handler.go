package handlers

import (
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/log"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type CreateOAuthClientRequest struct {
	AppName string   `json:"appName"`
	Scopes  []string `json:"scopes"`
}

type CreateOAuthClientResponse struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"` // Only returned on creation
	AppName      string `json:"appName"`
}

func CreateOAuthClientHandler(db *gorm.DB, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req CreateOAuthClientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "Missing or invalid token")
			return
		}

		tenantID, err := uuid.Parse(claims.TenantID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid tenant ID in token")
			return
		}

		if req.AppName == "" {
			writeError(w, http.StatusBadRequest, "Application name is required")
			return
		}

		// Generate Client ID and Secret
		clientID := uuid.New().String()
		clientSecret := auth.GenerateSecureToken() // A 32-byte secure random token

		// Hash the client secret for storage
		hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			log.Logger.Error().Err(err).Msg("Failed to hash client secret")
			writeError(w, http.StatusInternalServerError, "Failed to create client credentials")
			return
		}

		oauthClient := models.OAuthClient{
			ID:           uuid.New(),
			TenantID:     tenantID,
			ClientID:     clientID,
			ClientSecret: string(hashedSecret),
			AppName:      req.AppName,
			Scopes:       req.Scopes,
		}

		if err := db.Create(&oauthClient).Error; err != nil {
			log.Logger.Error().Err(err).Msg("Failed to save OAuth client")
			writeError(w, http.StatusInternalServerError, "Could not save client credentials")
			return
		}

		// Return the raw secret only once
		resp := CreateOAuthClientResponse{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			AppName:      req.AppName,
		}

		writeJSON(w, http.StatusCreated, resp)
	}
}

type ListOAuthClientsResponse struct {
	ID        uuid.UUID `json:"id"`
	AppName   string    `json:"appName"`
	ClientID  string    `json:"clientId"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"createdAt"`
}

func ListOAuthClientsHandler(db *gorm.DB, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		var clients []models.OAuthClient
		tenantID, _ := uuid.Parse(claims.TenantID)
		if err := db.Where("tenant_id = ? AND revoked = ?", tenantID, false).Find(&clients).Error; err != nil {
			log.Logger.Error().Err(err).Msg("Failed to list OAuth clients")
			writeError(w, http.StatusInternalServerError, "Could not retrieve clients")
			return
		}

		resp := make([]ListOAuthClientsResponse, len(clients))
		for i, c := range clients {
			resp[i] = ListOAuthClientsResponse{
				ID:        c.ID,
				AppName:   c.AppName,
				ClientID:  c.ClientID,
				Scopes:    c.Scopes,
				CreatedAt: c.CreatedAt,
			}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func RevokeOAuthClientHandler(db *gorm.DB, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		clientID := r.URL.Query().Get("clientId")
		if clientID == "" {
			writeError(w, http.StatusBadRequest, "Client ID is required")
			return
		}

		tenantID, _ := uuid.Parse(claims.TenantID)
		result := db.Model(&models.OAuthClient{}).Where("client_id = ? AND tenant_id = ?", clientID, tenantID).Update("revoked", true)

		if result.Error != nil {
			log.Logger.Error().Err(result.Error).Msg("Failed to revoke OAuth client")
			writeError(w, http.StatusInternalServerError, "Could not revoke client")
			return
		}

		if result.RowsAffected == 0 {
			writeError(w, http.StatusNotFound, "Client not found or you do not have permission to revoke it")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
