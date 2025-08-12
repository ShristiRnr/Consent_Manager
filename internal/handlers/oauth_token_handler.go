package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"

	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/log"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/golang-jwt/jwt/v4"
)

// OAuthTokenRequest defines the structure for a token request.
type OAuthTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// OAuthTokenResponse defines the structure for a successful token response.
type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// OAuthTokenHandler handles the token issuance for the client_credentials grant type.
func OAuthTokenHandler(db *gorm.DB, privateKey *rsa.PrivateKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req OAuthTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if req.GrantType != "client_credentials" {
			writeError(w, http.StatusBadRequest, "Unsupported grant_type")
			return
		}

		var client models.OAuthClient
		if err := db.Where("client_id = ?", req.ClientID).First(&client).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				writeError(w, http.StatusUnauthorized, "Invalid client credentials")
				return
			}
			log.Logger.Error().Err(err).Msg("Database error while fetching OAuth client")
			writeError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		if client.Revoked {
			writeError(w, http.StatusUnauthorized, "Client has been revoked")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(req.ClientSecret)); err != nil {
			writeError(w, http.StatusUnauthorized, "Invalid client credentials")
			return
		}

		// Generate JWT access token
		expirationTime := time.Now().Add(1 * time.Hour)
		claims := &auth.FiduciaryClaims{
			TenantID: client.TenantID.String(),
			Type:     "api",
			Role:     "api_client", // Assign a specific role for API clients
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   client.ClientID,
				ExpiresAt: jwt.NewNumericDate(expirationTime),
				Issuer:    "consent-manager",
				Audience:  jwt.ClaimStrings(client.Scopes),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			log.Logger.Error().Err(err).Msg("Failed to generate access token")
			writeError(w, http.StatusInternalServerError, "Failed to generate token")
			return
		}

		resp := OAuthTokenResponse{
			AccessToken: tokenString,
			TokenType:   "Bearer",
			ExpiresIn:   3600, // 1 hour in seconds
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
