package handlers

import (
	"consultrnr/consent-manager/internal/auth"
	contextKey "consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/repository"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/log"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// ListAllFiduciariesHandler provides comprehensive fiduciary management endpoints
func ListAllFiduciariesHandler(fiduciaryService *services.FiduciaryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		params := repository.FiduciaryListParams{
			Page:     1,
			Limit:    20,
			Search:   r.URL.Query().Get("search"),
			Role:     r.URL.Query().Get("role"),
			SortBy:   r.URL.Query().Get("sortBy"),
			SortDesc: r.URL.Query().Get("sortDesc") == "true",
		}

		// Parse page
		if pageStr := r.URL.Query().Get("page"); pageStr != "" {
			if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
				params.Page = page
			}
		}

		// Parse limit
		if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
			if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
				params.Limit = limit
			}
		}

		// Parse tenant ID if provided
		if tenantIDStr := r.URL.Query().Get("tenantId"); tenantIDStr != "" {
			if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
				params.TenantID = &tenantID
			}
		}

		// Get fiduciaries
		response, err := fiduciaryService.ListFiduciaries(params)
		if err != nil {
			log.Logger.Error().Err(err).Msg("failed to list fiduciary users")
			writeError(w, http.StatusInternalServerError, "failed to list fiduciary users")
			return
		}

		writeJSON(w, http.StatusOK, response)
	}
}

func GetFiduciaryByIDHandler(fiduciaryService *services.FiduciaryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		fiduciaryIDStr := vars["fiduciaryId"]

		fiduciaryID, err := uuid.Parse(fiduciaryIDStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid fiduciary ID")
			return
		}

		fiduciary, err := fiduciaryService.GetFiduciaryByID(fiduciaryID)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				writeError(w, http.StatusNotFound, "fiduciary user not found")
				return
			}
			log.Logger.Error().Err(err).Msg("failed to get fiduciary user")
			writeError(w, http.StatusInternalServerError, "failed to get fiduciary user")
			return
		}

		writeJSON(w, http.StatusOK, fiduciary)
	}
}

func CreateNewFiduciaryHandler(fiduciaryService *services.FiduciaryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req services.CreateFiduciaryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		fiduciary, err := fiduciaryService.CreateFiduciary(&req)
		if err != nil {
			log.Logger.Error().Err(err).Msg("failed to create fiduciary user")
			if strings.Contains(err.Error(), "already exists") {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			if strings.Contains(err.Error(), "validation") || strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "invalid") {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to create fiduciary user")
			return
		}

		writeJSON(w, http.StatusCreated, fiduciary)
	}
}

func UpdateFiduciaryDataHandler(fiduciaryService *services.FiduciaryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		fiduciaryIDStr := vars["fiduciaryId"]

		fiduciaryID, err := uuid.Parse(fiduciaryIDStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid fiduciary ID")
			return
		}

		// Authorization: only admins can update fiduciaries
		_, ok := r.Context().Value(contextKey.FiduciaryClaimsKey).(*auth.FiduciaryClaims)
		if !ok {
			writeError(w, http.StatusForbidden, "fiduciary access required")
			return
		}

		var req services.UpdateFiduciaryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		fiduciary, err := fiduciaryService.UpdateFiduciary(fiduciaryID, &req)
		if err != nil {
			log.Logger.Error().Err(err).Msg("failed to update fiduciary user")
			if err == gorm.ErrRecordNotFound {
				writeError(w, http.StatusNotFound, "fiduciary user not found")
				return
			}
			if strings.Contains(err.Error(), "validation") || strings.Contains(err.Error(), "invalid") {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to update fiduciary user")
			return
		}

		writeJSON(w, http.StatusOK, fiduciary)
	}
}

func DeleteFiduciaryByIDHandler(fiduciaryService *services.FiduciaryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		fiduciaryIDStr := vars["fiduciaryId"]

		fiduciaryID, err := uuid.Parse(fiduciaryIDStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid fiduciary ID")
			return
		}

		// Authorization: only admins can delete fiduciaries
		_, ok := r.Context().Value(contextKey.FiduciaryClaimsKey).(*auth.FiduciaryClaims)
		if !ok {
			writeError(w, http.StatusForbidden, "fiduciary access required")
			return
		}

		err = fiduciaryService.DeleteFiduciary(fiduciaryID)
		if err != nil {
			log.Logger.Error().Err(err).Msg("failed to delete fiduciary user")
			if err == gorm.ErrRecordNotFound {
				writeError(w, http.StatusNotFound, "fiduciary user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to delete fiduciary user")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// FiduciaryStatsHandler provides fiduciary statistics for dashboard
func FiduciaryStatsHandler(fiduciaryService *services.FiduciaryService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get basic stats
		allFiduciaries, err := fiduciaryService.ListFiduciaries(repository.FiduciaryListParams{
			Page:  1,
			Limit: 10000, // Get all fiduciaries for stats
		})
		if err != nil {
			log.Logger.Error().Err(err).Msg("failed to get fiduciary stats")
			writeError(w, http.StatusInternalServerError, "failed to get fiduciary stats")
			return
		}

		// Calculate role distribution
		roleStats := make(map[string]int)

		for _, fiduciary := range allFiduciaries.Users {
			roleStats[fiduciary.Role]++
		}

		stats := map[string]interface{}{
			"totalFiduciaries": allFiduciaries.Total,
			"roleDistribution": roleStats,
		}

		writeJSON(w, http.StatusOK, stats)
	}
}
