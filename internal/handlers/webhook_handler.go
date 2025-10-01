package handlers

import (
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

type WebhookHandler struct {
	DB *gorm.DB
}

func NewWebhookHandler(db *gorm.DB) *WebhookHandler {
	return &WebhookHandler{DB: db}
}

type CreateWebhookRequest struct {
	URL        string   `json:"url"`
	EventTypes []string `json:"eventTypes"`
}

// CreateWebhook creates a new webhook endpoint for the current tenant.
func (h *WebhookHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	tenantID, _ := uuid.Parse(claims.TenantID)

	var req CreateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Generate a secure secret for signing payloads
	secret := auth.GenerateSecureToken()

	webhook := models.Webhook{
		ID:         uuid.New(),
		TenantID:   tenantID,
		URL:        req.URL,
		Secret:     secret,
		EventTypes: req.EventTypes,
		IsActive:   true,
	}

	if err := h.DB.Create(&webhook).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create webhook")
		return
	}

	// Create a response that includes the secret only on creation
	type CreateWebhookResponse struct {
		models.Webhook
		Secret string `json:"secret"`
	}

	resp := CreateWebhookResponse{
		Webhook: webhook,
		Secret:  secret, // Return the secret to the user ONCE
	}
	// Clear the secret from the persisted model to avoid accidentally logging it
	resp.Webhook.Secret = ""

	writeJSON(w, http.StatusCreated, resp)
}

// ListWebhooks lists all webhooks for the current tenant.
func (h *WebhookHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	tenantID, _ := uuid.Parse(claims.TenantID)

	var webhooks []models.Webhook
	if err := h.DB.Where("tenant_id = ?", tenantID).Find(&webhooks).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list webhooks")
		return
	}

	// Never expose secrets in the list view
	for i := range webhooks {
		webhooks[i].Secret = ""
	}

	writeJSON(w, http.StatusOK, webhooks)
}

// DeleteWebhook deletes a webhook.
func (h *WebhookHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	tenantID, _ := uuid.Parse(claims.TenantID)
	webhookID, err := uuid.Parse(mux.Vars(r)["webhookId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid webhook ID")
		return
	}

	// Ensure the webhook belongs to the caller's tenant before deleting
	result := h.DB.Where("id = ? AND tenant_id = ?", webhookID, tenantID).Delete(&models.Webhook{})
	if result.Error != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete webhook")
		return
	}
	if result.RowsAffected == 0 {
		writeError(w, http.StatusNotFound, "Webhook not found or you do not have permission to delete it")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
