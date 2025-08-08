package handlers

import (
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
)

type CreatePurposeRequest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	DataObjects  pq.StringArray `json:"data_objects"` 
	ReviewCycleMonths int `json:"review_cycle_months"`
	Vendors      []string `json:"vendors"`
	IsThirdParty bool     `json:"is_third_party"`
	Required     bool     `json:"required"`
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
		claims := r.Context().Value(contextkeys.AdminClaimsKey)
		if claims == nil {
			http.Error(w, "unauthorized: no claims", http.StatusUnauthorized)
			return
		}
		adminClaims, ok := claims.(*auth.AdminClaims)
		if !ok {
			http.Error(w, "unauthorized: bad claims", http.StatusUnauthorized)
			return
		}
		tenantID := adminClaims.TenantID
		// Now, get your tenant db etc using tenantID
		schema := "tenant_" + tenantID[:8]
		dbConn, err := db.GetTenantDB(schema)
		if err != nil || dbConn == nil {
			http.Error(w, "tenant db not found", http.StatusInternalServerError)
			return
		}

		var req CreatePurposeRequest
		// IsThirdParty is optional, default to false
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if req.Description == "" {
			http.Error(w, "description is required", http.StatusBadRequest)
			return
		}

		//if IsThirdParty is true then vendors must be provided
		if req.IsThirdParty && len(req.Vendors) == 0 {
			http.Error(w, "vendors are required for third-party purposes", http.StatusBadRequest)
			return
		}

		// if IsThirdParty is false then vendors must be empty
		if !req.IsThirdParty && len(req.Vendors) > 0 {
			http.Error(w, "vendors must be empty for non-third-party purposes", http.StatusBadRequest)
			return
		}

		purpose := &models.Purpose{
			ID:           uuid.New(),
			Name:         req.Name,
			Description:  req.Description,
			Vendors:      req.Vendors,
			// DataObjects:  req.DataObjects,
			ReviewCycleMonths: req.ReviewCycleMonths,
			IsThirdParty: req.IsThirdParty,
			Required:     req.Required,
			Active:       true,
			TenantID:     uuid.MustParse(tenantID),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if err := dbConn.Create(purpose).Error; err != nil {
			log.Printf("[ERROR] Failed to create purpose: %v", err)
			http.Error(w, "failed to create purpose", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(purpose)
	}
}

func (h *PurposeHandler) ToggleActive(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(contextkeys.AdminClaimsKey)
	if claims == nil {
		http.Error(w, "unauthorized: no claims", http.StatusUnauthorized)
		return
	}
	adminClaims, ok := claims.(*auth.AdminClaims)
	if !ok {
		http.Error(w, "unauthorized: bad claims", http.StatusUnauthorized)
		return
	}
	tenantID := adminClaims.TenantID
	// Now, get your tenant db etc using tenantID
	schema := "tenant_" + tenantID[:8]
	dbConn, err := db.GetTenantDB(schema)
	if err != nil || dbConn == nil {
		http.Error(w, "tenant db not found", http.StatusInternalServerError)
		return
	}
	idStr := mux.Vars(r)["id"]
	var payload struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var purpose models.Purpose
	if err := h.DB.First(&purpose, "id = ?", id).Error; err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	purpose.Active = payload.Active
	if err := h.DB.Save(&purpose).Error; err != nil {
		http.Error(w, "failed to update", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(purpose)
}

func ListPurposesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(contextkeys.AdminClaimsKey)
		if claims == nil {
			http.Error(w, "unauthorized: no claims", http.StatusUnauthorized)
			return
		}
		adminClaims, ok := claims.(*auth.AdminClaims)
		if !ok {
			http.Error(w, "unauthorized: bad claims", http.StatusUnauthorized)
			return
		}
		tenantID := adminClaims.TenantID
		// Now, get your tenant db etc using tenantID
		schema := "tenant_" + tenantID[:8]
		dbConn, err := db.GetTenantDB(schema)
		if err != nil || dbConn == nil {
			http.Error(w, "tenant db not found", http.StatusInternalServerError)
			return
		}
		// The rest as you already have...
		var purposes []models.Purpose
		if err := dbConn.Where("tenant_id = ?", tenantID).Find(&purposes).Error; err != nil {
			log.Printf("[ERROR] Failed to fetch purposes: %v", err)
			http.Error(w, "failed to fetch purposes", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(purposes)
	}
}

// Get /api/v1/user/purposes/{id}
func UserGetPurposeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1) auth header
		userHeader := r.Header.Get("Authorization")
		if userHeader == "" {
			writeErr(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		parts := strings.SplitN(userHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeErr(w, http.StatusUnauthorized, "invalid Authorization header format")
			return
		}

		// 2) parse user token
		parsedToken, err := auth.ParseUserToken(parts[1], publicKey)
		if err != nil {
			log.Printf("error parsing user token: %v", err)
			writeErr(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		uid, err := uuid.Parse(parsedToken.UserID)
		if err != nil || uid == uuid.Nil {
			log.Printf("error parsing user ID: %v", err)
			writeErr(w, http.StatusUnauthorized, "unauthorized - invalid user ID")
			return
		}

		// 3) tenant lookup
		tid, err := GetUserTenantLink(userHeader)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to fetch tenant link")
			return
		}
		schema := "tenant_" + tid.String()[:8]
		tenantDB, err := db.GetTenantDB(schema)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "tenant DB not found")
			return
		}

		// 4) parse path param
		vars := mux.Vars(r)
		idStr := vars["id"]
		id, err := uuid.Parse(idStr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid purpose ID")
			return
		}

		// 5) fetch single purpose
		var purpose models.Purpose
		if err := tenantDB.
			Where("id = ? AND tenant_id = ?", id, tid).
			First(&purpose).
			Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				writeErr(w, http.StatusNotFound, "purpose not found")
			} else {
				log.Printf("[ERROR] failed to fetch purpose: %v", err)
				writeErr(w, http.StatusInternalServerError, "failed to fetch purpose")
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
		// 1) auth header
		userHeader := r.Header.Get("Authorization")
		if userHeader == "" {
			writeErr(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		parts := strings.SplitN(userHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeErr(w, http.StatusUnauthorized, "invalid Authorization header format")
			return
		}

		// 2) parse user token
		parsedToken, err := auth.ParseUserToken(parts[1], publicKey)
		if err != nil {
			log.Printf("error parsing user token: %v", err)
			writeErr(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		uid, err := uuid.Parse(parsedToken.UserID)
		if err != nil || uid == uuid.Nil {
			log.Printf("error parsing user ID: %v", err)
			writeErr(w, http.StatusUnauthorized, "unauthorized - invalid user ID")
			return
		}

		vars := mux.Vars(r)
		idStr := vars["tenantID"]
		id, err := uuid.Parse(idStr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid tenant ID")
			return
		}

		// 3) tenant db
		schema := "tenant_" + id.String()[:8]
		tenantDB, err := db.GetTenantDB(schema)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "tenant DB not found")
			return
		}
		// 4) fetch purposes for this tenant and user
		var purposes []models.Purpose
		if err := tenantDB.
			Where("tenant_id = ? AND active = true", id).
			Find(&purposes).Error; err != nil {
			log.Printf("[ERROR] failed to fetch purposes: %v", err)
			writeErr(w, http.StatusInternalServerError, "failed to fetch purposes")
			return
		}
		if len(purposes) == 0 {
			writeErr(w, http.StatusNotFound, "no purposes found for this tenant")
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
		claims := r.Context().Value(contextkeys.AdminClaimsKey)
		if claims == nil {
			http.Error(w, "unauthorized: no claims", http.StatusUnauthorized)
			return
		}
		adminClaims, ok := claims.(*auth.AdminClaims)
		if !ok {
			http.Error(w, "unauthorized: bad claims", http.StatusUnauthorized)
			return
		}
		tenantID := adminClaims.TenantID
		// Now, get your tenant db etc using tenantID
		schema := "tenant_" + tenantID[:8]
		dbConn, err := db.GetTenantDB(schema)
		if err != nil || dbConn == nil {
			http.Error(w, "tenant db not found", http.StatusInternalServerError)
			return
		}

		purposeID := r.URL.Query().Get("id")
		if purposeID == "" {
			http.Error(w, "missing purpose ID", http.StatusBadRequest)
			return
		}

		if err := dbConn.Where("id = ? AND tenant_id = ?", purposeID, tenantID).Delete(&models.Purpose{}).Error; err != nil {
			log.Printf("[ERROR] Failed to delete purpose: %v", err)
			http.Error(w, "failed to delete purpose", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func UpdatePurposeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(contextkeys.AdminClaimsKey)
		if claims == nil {
			http.Error(w, "unauthorized: no claims", http.StatusUnauthorized)
			return
		}
		adminClaims, ok := claims.(*auth.AdminClaims)
		if !ok {
			http.Error(w, "unauthorized: bad claims", http.StatusUnauthorized)
			return
		}
		tenantID := adminClaims.TenantID
		// Now, get your tenant db etc using tenantID
		schema := "tenant_" + tenantID[:8]
		dbConn, err := db.GetTenantDB(schema)
		if err != nil || dbConn == nil {
			http.Error(w, "tenant db not found", http.StatusInternalServerError)
			return
		}

		var req CreatePurposeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		purposeID := r.URL.Query().Get("id")
		if purposeID == "" {
			http.Error(w, "missing purpose ID", http.StatusBadRequest)
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
			http.Error(w, "failed to update purpose", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(purpose)
	}
}
