package handlers

import (
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"encoding/json"
	"net/http"

	"consultrnr/consent-manager/pkg/log"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type IdentifyRequest struct {
	Email      string `json:"email,omitempty"`
	Phone      string `json:"phone,omitempty"`
	ExternalID string `json:"externalId,omitempty"`
}

type IdentifyResponse struct {
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

func IdentifyUserHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		tenantID, _ := uuid.Parse(claims.TenantID)

		var req IdentifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		query := db.Model(&models.DataPrincipal{}).Where("tenant_id = ?", tenantID)

		if req.Email != "" {
			query = query.Where("email = ?", req.Email)
		} else if req.Phone != "" {
			query = query.Where("phone = ?", req.Phone)
		} else if req.ExternalID != "" {
			query = query.Where("external_id = ?", req.ExternalID)
		} else {
			writeError(w, http.StatusBadRequest, "Either email, phone, or externalId is required")
			return
		}

		var user models.DataPrincipal
		if err := query.First(&user).Error; err != nil {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}

		log.Logger.Info().Str("fiduciaryId", claims.FiduciaryID).Str("dataPrincipalId", user.ID.String()).Msg("Data principal identified by fiduciary")

		resp := IdentifyResponse{UserID: user.ID.String(), Email: user.Email, FirstName: user.FirstName, LastName: user.LastName}
		writeJSON(w, http.StatusOK, resp)
	}
}
