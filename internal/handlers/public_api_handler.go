package handlers

import (
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type PublicAPIHandler struct {
	DB             *gorm.DB
	DSRService     *services.DSRService
	UserConsentSvc *services.UserConsentService
	AuditService   *services.AuditService
	WebhookSvc     *services.WebhookService
}

func NewPublicAPIHandler(db *gorm.DB, dsrService *services.DSRService, userConsentSvc *services.UserConsentService, auditService *services.AuditService, webhookSvc *services.WebhookService) *PublicAPIHandler {
	return &PublicAPIHandler{DB: db, DSRService: dsrService, UserConsentSvc: userConsentSvc, AuditService: auditService, WebhookSvc: webhookSvc}
}

// CreateDataPrincipal handles creating a new end-user via the public API.
func (h *PublicAPIHandler) CreateDataPrincipal(w http.ResponseWriter, r *http.Request) {
	apiKeyClaims := middlewares.GetAPIKeyClaims(r)
	if apiKeyClaims == nil {
		writeError(w, http.StatusUnauthorized, "Invalid API key claims")
		return
	}
	tenantID, _ := uuid.Parse(apiKeyClaims.TenantID)

	var req DataPrincipalSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to process password")
		return
	}

	dataPrincipal := models.DataPrincipal{
		ID:           uuid.New(),
		TenantID:     tenantID, // Set tenant from API key
		Email:        req.Email,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Phone:        req.Phone,
		PasswordHash: string(hashedPassword),
		IsVerified:   true, // Users created via API are considered verified
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := h.DB.Create(&dataPrincipal).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Could not create user")
		return
	}

	// Audit log
	go h.AuditService.Create(r.Context(), uuid.Nil, tenantID, dataPrincipal.ID, "data_principal_created_api", "created", "api_key", r.RemoteAddr, "", "", map[string]interface{}{"email": dataPrincipal.Email})

	writeJSON(w, http.StatusCreated, map[string]string{"userId": dataPrincipal.ID.String()})
}

// GetDataPrincipalConsents retrieves all consents for a given user within the tenant.
func (h *PublicAPIHandler) GetDataPrincipalConsents(w http.ResponseWriter, r *http.Request) {
	apiKeyClaims := middlewares.GetAPIKeyClaims(r)
	tenantID, _ := uuid.Parse(apiKeyClaims.TenantID) // This is used in the query below
	userID, err := uuid.Parse(mux.Vars(r)["userId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get tenant-specific DB connection
	schema := "tenant_" + apiKeyClaims.TenantID[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Tenant database not found")
		return
	}

	var consents []models.UserConsent
	if err := tenantDB.Where("user_id = ? AND tenant_id = ?", userID, tenantID).Find(&consents).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve consents")
		return
	}

	writeJSON(w, http.StatusOK, consents)
}

// CreateDSR creates a Data Subject Request for a user.
func (h *PublicAPIHandler) CreateDSR(w http.ResponseWriter, r *http.Request) {
	apiKeyClaims := middlewares.GetAPIKeyClaims(r)
	tenantID, _ := uuid.Parse(apiKeyClaims.TenantID)

	var req struct {
		UserID string `json:"userId"`
		Type   string `json:"type"` // e.g., "Data Deletion", "Data Portability"
		Note   string `json:"note,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	// Get tenant-specific DB connection
	schema := "tenant_" + apiKeyClaims.TenantID[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Tenant database not found")
		return
	}

	dsrRequest := models.DSRRequest{
		ID:             uuid.New(),
		UserID:         userID,
		TenantID:       tenantID,
		Type:           req.Type,
		Status:         "Pending",
		RequestedAt:    time.Now(),
		ResolutionNote: req.Note,
	}

	if err := tenantDB.Create(&dsrRequest).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create DSR request")
		return
	}

	// Audit log
	go h.AuditService.Create(r.Context(), uuid.Nil, tenantID, userID, "dsr_created_api", "created", "api_key", r.RemoteAddr, "", "", map[string]interface{}{
		"dsrId":   dsrRequest.ID.String(),
		"dsrType": dsrRequest.Type,
	})

	writeJSON(w, http.StatusCreated, dsrRequest)
}

// VerifyConsentsRequest is the request body for checking required consents.
type VerifyConsentsRequest struct {
	UserID        string `json:"userId"`
	ConsentFormID string `json:"consentFormId"`
}

// VerifyConsentsResponse is the response for the consent verification check.
type VerifyConsentsResponse struct {
	Status                  string           `json:"status"` // "granted" or "denied"
	UserID                  string           `json:"userId"`
	ConsentFormID           string           `json:"consentFormId"`
	MissingRequiredConsents []MissingConsent `json:"missingRequiredConsents,omitempty"`
}

type MissingConsent struct {
	PurposeID   string `json:"purposeId"`
	PurposeName string `json:"purposeName"`
}

// VerifyConsents checks if a user has granted all required consents for a given form.
func (h *PublicAPIHandler) VerifyConsents(w http.ResponseWriter, r *http.Request) {
	apiKeyClaims := middlewares.GetAPIKeyClaims(r)
	tenantID, _ := uuid.Parse(apiKeyClaims.TenantID)

	var req VerifyConsentsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid userId format")
		return
	}
	formID, err := uuid.Parse(req.ConsentFormID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid consentFormId format")
		return
	}

	// Get tenant-specific DB connection
	schema := "tenant_" + apiKeyClaims.TenantID[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Tenant database not found")
		return
	}

	// 1. Find all required purposes for the consent form
	var requiredPurposes []models.Purpose
	if err := tenantDB.Joins("JOIN consent_form_purposes on consent_form_purposes.purpose_id = purposes.id").
		Where("consent_form_purposes.consent_form_id = ? AND purposes.required = ?", formID, true).
		Find(&requiredPurposes).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Could not retrieve required purposes")
		return
	}

	// 2. Find the user's granted consents for those purposes
	var grantedConsents []models.UserConsent
	var requiredPurposeIDs []uuid.UUID
	for _, p := range requiredPurposes {
		requiredPurposeIDs = append(requiredPurposeIDs, p.ID)
	}

	if len(requiredPurposeIDs) > 0 {
		tenantDB.Where("user_id = ? AND purpose_id IN ? AND status = ?", userID, requiredPurposeIDs, true).Find(&grantedConsents)
	}

	// 3. Check for missing consents
	grantedMap := make(map[uuid.UUID]bool)
	for _, gc := range grantedConsents {
		grantedMap[gc.PurposeID] = true
	}

	var missingConsents []MissingConsent
	for _, rp := range requiredPurposes {
		if !grantedMap[rp.ID] {
			missingConsents = append(missingConsents, MissingConsent{
				PurposeID:   rp.ID.String(),
				PurposeName: rp.Name,
			})
		}
	}

	if len(missingConsents) > 0 {
		// Dispatch a webhook event for a failed verification
		go h.WebhookSvc.Dispatch(tenantID, "consent.verification.failed", map[string]interface{}{
			"userId":                  req.UserID,
			"consentFormId":           req.ConsentFormID,
			"missingRequiredConsents": missingConsents,
			"checkedAt":               time.Now(),
		})

		writeJSON(w, http.StatusOK, VerifyConsentsResponse{
			Status:                  "denied",
			UserID:                  req.UserID,
			ConsentFormID:           req.ConsentFormID,
			MissingRequiredConsents: missingConsents,
		})
		return
	}

	// Dispatch a webhook event for a successful verification
	go h.WebhookSvc.Dispatch(tenantID, "consent.verification.succeeded", map[string]interface{}{
		"userId":        req.UserID,
		"consentFormId": req.ConsentFormID,
		"checkedAt":     time.Now(),
	})

	writeJSON(w, http.StatusOK, VerifyConsentsResponse{
		Status:        "granted",
		UserID:        req.UserID,
		ConsentFormID: req.ConsentFormID,
	})
}

// SubmitConsentViaAPI allows a fiduciary's backend to submit consent on behalf of a user.
func (h *PublicAPIHandler) SubmitConsentViaAPI(w http.ResponseWriter, r *http.Request) {
	apiKeyClaims := middlewares.GetAPIKeyClaims(r)
	tenantID, err := uuid.Parse(apiKeyClaims.TenantID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Invalid tenant ID in API key")
		return
	}

	var req dto.SubmitConsentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	// The request body must contain the UserID and FormID
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid or missing userId in request body")
		return
	}

	formID, err := uuid.Parse(req.ConsentFormID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid or missing consentFormId in request body")
		return
	}

	// The service layer handles the logic of creating/updating UserConsent records
	if err := h.UserConsentSvc.SubmitConsent(userID, tenantID, formID, &req); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to process consent submission: "+err.Error())
		return
	}

	// Dispatch a webhook event for the consent update
	go h.WebhookSvc.Dispatch(tenantID, "consent.updated", map[string]interface{}{
		"userId":        req.UserID,
		"consentFormId": req.ConsentFormID,
		"purposes":      req.Purposes,
		"updatedAt":     time.Now(),
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "Consent submitted successfully."})
}
