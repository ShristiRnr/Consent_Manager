package handlers

import (
	"net/http"

	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// ListConsentsHandler returns a handler function for listing all consents
func ListConsentsHandler(consentService *services.ConsentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get fiduciary claims from context
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Parse tenant ID from claims
		tenantID, err := uuid.Parse(claims.TenantID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid tenant ID")
			return
		}

		// Get tenant DB based on tenant ID
		tenantSchema := "tenant_" + tenantID.String()[:8]
		tenantDB, err := db.GetTenantDB(tenantSchema)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get tenant database")
			return
		}

		// Get all consents for the tenant
		consents, err := consentService.GetAllConsentsByTenant(r.Context(), tenantDB, tenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get consents")
			return
		}

		// Ensure we return an empty array instead of null
		if consents == nil {
			consents = []models.Consent{}
		}

		writeJSON(w, http.StatusOK, consents)
	}
}

// GetConsentByIDHandler returns a handler function for getting a specific consent by ID
func GetConsentByIDHandler(consentService *services.ConsentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get fiduciary claims from context
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Parse tenant ID from claims
		tenantID, err := uuid.Parse(claims.TenantID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid tenant ID")
			return
		}

		// Get consent ID from URL
		vars := mux.Vars(r)
		consentID := vars["consentId"]
		if consentID == "" {
			writeError(w, http.StatusBadRequest, "missing consent ID")
			return
		}

		// Parse user ID from consent ID
		// Note: In a real implementation, you would likely have a more direct way to get a consent by ID
		// This is a simplified approach assuming consent IDs are user IDs
		userID, err := uuid.Parse(consentID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid consent ID")
			return
		}

		// Get tenant DB based on tenant ID
		tenantSchema := "tenant_" + tenantID.String()[:8]
		tenantDB, err := db.GetTenantDB(tenantSchema)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get tenant database")
			return
		}

		// Get the consent
		consent, err := consentService.GetUserConsentInTenant(r.Context(), tenantDB, tenantID, userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get consent")
			return
		}

		if consent == nil {
			writeError(w, http.StatusNotFound, "consent not found")
			return
		}

		writeJSON(w, http.StatusOK, consent)
	}
}
