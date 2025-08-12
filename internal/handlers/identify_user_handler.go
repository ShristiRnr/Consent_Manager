package handlers

import (
	"encoding/json"
	"net/http"

	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/log"

	"github.com/google/uuid"
)

type IdentifyRequest struct {
	UserID string `json:"userId"`
}

func identifyUserHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get claims from context (populated by middleware)
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized: not a fiduciary user")
		return
	}

	// 2. Decode JSON body
	var req IdentifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// 3. Parse UUID
	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid userId format")
		return
	}

	// 4. Lookup user in master DB
	masterDB := db.GetMasterDB()
	var dp models.DataPrincipal
	if err := masterDB.First(&dp, userUUID).Error; err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	log.Logger.Info().
		Str("fiduciaryId", claims.FiduciaryID).
		Str("dataPrincipalId", dp.ID.String()).
		Msg("Data principal lookup by fiduciary")

	// 5. Return JSON with email
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"userId": dp.ID.String(),
		"email":  dp.Email,
	})
}
