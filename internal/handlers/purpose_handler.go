package handlers

import (
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type CreatePurposeRequest struct {
	Name              string         `json:"name"`
	Description       string         `json:"description"`
	DataObjects       pq.StringArray `json:"data_objects"`
	ReviewCycleMonths int            `json:"review_cycle_months"`
	Vendors           []string       `json:"vendors"`
	IsThirdParty      bool           `json:"is_third_party"`
	Required          bool           `json:"required"`
}

// PurposeHandler handles purpose-related requests
type PurposeHandler struct {
	DB *gorm.DB
}

func NewPurposeHandler(db *gorm.DB) *PurposeHandler {
	return &PurposeHandler{
		DB: db,
	}
}

func CreatePurposeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusForbidden, "fiduciary access required")
			return
		}
		tenantID := claims.TenantID
		// Now, get your tenant db etc using tenantID
		schema := "tenant_" + tenantID[:8]
		dbConn, err := db.GetTenantDB(schema)
		if err != nil || dbConn == nil {
			writeError(w, http.StatusInternalServerError, "tenant db not found")
			return
		}

		var req CreatePurposeRequest
		// IsThirdParty is optional, default to false
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
		if req.Description == "" {
			writeError(w, http.StatusBadRequest, "description is required")
			return
		}

		//if IsThirdParty is true then vendors must be provided
		if req.IsThirdParty && len(req.Vendors) == 0 {
			writeError(w, http.StatusBadRequest, "vendors are required for third-party purposes")
			return
		}

		// if IsThirdParty is false then vendors must be empty
		if !req.IsThirdParty && len(req.Vendors) > 0 {
			writeError(w, http.StatusBadRequest, "vendors must be empty for non-third-party purposes")
			return
		}

		purpose := &models.Purpose{
			ID:                uuid.New(),
			Name:              req.Name,
			Description:       req.Description,
			Vendors:           req.Vendors,
			ReviewCycleMonths: req.ReviewCycleMonths,
			IsThirdParty:      req.IsThirdParty,
			Required:          req.Required,
			Active:            true,
			TenantID:          uuid.MustParse(tenantID),
			CreatedAt:         time.Now(),
			UpdatedAt:         time.Now(),
		}

		if err := dbConn.Create(purpose).Error; err != nil {
			log.Printf("[ERROR] Failed to create purpose: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to create purpose")
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(purpose)
	}
}

func (h *PurposeHandler) ToggleActive(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusForbidden, "fiduciary access required")
		return
	}
	tenantID := claims.TenantID
	// Now, get your tenant db etc using tenantID
	schema := "tenant_" + tenantID[:8]
	dbConn, err := db.GetTenantDB(schema)
	if err != nil || dbConn == nil {
		writeError(w, http.StatusInternalServerError, "tenant db not found")
		return
	}
	idStr := mux.Vars(r)["id"]
	var payload struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	var purpose models.Purpose
	if err := dbConn.First(&purpose, "id = ?", idStr).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			writeError(w, http.StatusNotFound, "purpose not found")
		} else {
			writeError(w, http.StatusInternalServerError, "database error")
		}
		return
	}

	purpose.Active = payload.Active
	if err := dbConn.Save(&purpose).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update purpose")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(purpose)
}

func ListPurposesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusForbidden, "fiduciary access required")
			return
		}
		tenantID := claims.TenantID
		// Now, get your tenant db etc using tenantID
		schema := "tenant_" + tenantID[:8]
		dbConn, err := db.GetTenantDB(schema)
		if err != nil || dbConn == nil {
			writeError(w, http.StatusInternalServerError, "tenant db not found")
			return
		}

		var purposes []models.Purpose
		if err := dbConn.Find(&purposes).Error; err != nil {
			log.Printf("[ERROR] Failed to list purposes: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to list purposes")
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(purposes)
	}
}

// Get /api/v1/user/purposes/{id}
func UserGetPurposeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
		if !ok {
			writeError(w, http.StatusForbidden, "user access required")
			return
		}

		// 3) tenant lookup
		tid, err := uuid.Parse(claims.TenantID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid tenant id in claims")
			return
		}

		schema := "tenant_" + tid.String()[:8]
		tenantDB, err := db.GetTenantDB(schema)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "tenant DB not found")
			return
		}

		// 4) parse path param
		vars := mux.Vars(r)
		idStr := vars["id"]
		id, err := uuid.Parse(idStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid purpose ID")
			return
		}

		// 5) fetch single purpose
		var purpose models.Purpose
		if err := tenantDB.
			Where("id = ? AND tenant_id = ?", id, tid).
			First(&purpose).
			Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				writeError(w, http.StatusNotFound, "purpose not found")
			} else {
				log.Printf("[ERROR] failed to fetch purpose: %v", err)
				writeError(w, http.StatusInternalServerError, "failed to fetch purpose")
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(purpose)
	}
}

// GET /api/v1/user/purposes/{tenantID}
func UserGetPurposeByTenant() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
		if !ok {
			writeError(w, http.StatusForbidden, "user access required")
			return
		}

		vars := mux.Vars(r)
		idStr := vars["tenantID"]
		id, err := uuid.Parse(idStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid tenant ID")
			return
		}

		// Authorize: ensure the user is accessing their own tenant's data
		if claims.TenantID != idStr {
			writeError(w, http.StatusForbidden, "you are not authorized to access this tenant's data")
			return
		}

		// 3) tenant db
		schema := "tenant_" + id.String()[:8]
		tenantDB, err := db.GetTenantDB(schema)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "tenant DB not found")
			return
		}
		// 4) fetch purposes for this tenant and user
		var purposes []models.Purpose
		if err := tenantDB.
			Where("tenant_id = ? AND active = true", id).
			Find(&purposes).Error; err != nil {
			log.Printf("[ERROR] failed to fetch purposes: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to fetch purposes")
			return
		}
		if len(purposes) == 0 {
			writeError(w, http.StatusNotFound, "no purposes found for this tenant")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(purposes); err != nil {
			log.Printf("[ERROR] failed to encode purposes: %v", err)
			http.Error(w, "failed to encode purposes", http.StatusInternalServerError)
			return
		}
	}
}

func DeletePurposeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusForbidden, "fiduciary access required")
			return
		}
		tenantID := claims.TenantID
		// Now, get your tenant db etc using tenantID
		schema := "tenant_" + tenantID[:8]
		dbConn, err := db.GetTenantDB(schema)
		if err != nil || dbConn == nil {
			writeError(w, http.StatusInternalServerError, "tenant db not found")
			return
		}

		purposeID := r.URL.Query().Get("id")
		if purposeID == "" {
			writeError(w, http.StatusBadRequest, "missing purpose ID")
			return
		}

		if err := dbConn.Where("id = ? AND tenant_id = ?", purposeID, tenantID).Delete(&models.Purpose{}).Error; err != nil {
			log.Printf("[ERROR] Failed to delete purpose: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to delete purpose")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func UpdatePurposeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusForbidden, "fiduciary access required")
			return
		}
		tenantID := claims.TenantID
		// Now, get your tenant db etc using tenantID
		schema := "tenant_" + tenantID[:8]
		dbConn, err := db.GetTenantDB(schema)
		if err != nil || dbConn == nil {
			writeError(w, http.StatusInternalServerError, "tenant db not found")
			return
		}

		var req CreatePurposeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}

		purposeID := r.URL.Query().Get("id")
		if purposeID == "" {
			writeError(w, http.StatusBadRequest, "missing purpose ID")
			return
		}

		purpose := &models.Purpose{
			ID:          uuid.MustParse(purposeID),
			Name:        req.Name,
			Description: req.Description,
			Required:    req.Required,
			TenantID:    uuid.MustParse(tenantID),
			UpdatedAt:   time.Now(),
		}

		if err := dbConn.Model(&models.Purpose{}).Where("id = ? AND tenant_id = ?", purpose.ID, tenantID).Updates(purpose).Error; err != nil {
			log.Printf("[ERROR] Failed to update purpose: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to update purpose")
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(purpose)
	}
}
