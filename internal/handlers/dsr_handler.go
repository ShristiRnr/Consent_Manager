package handlers

import (
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

type DataRequestHandler struct {
	DB *gorm.DB
}

func NewDataRequestHandler(db *gorm.DB) *DataRequestHandler {
	return &DataRequestHandler{DB: db}
}

// ListAdminRequests lists all data requests for admins
func (h *DataRequestHandler) ListAdminRequests(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var requests []models.DSRRequest
	if err := h.DB.
		Where("status = ?", "Pending").
		Find(&requests).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, requests)
}

// GetAdminRequestDetails retrieves details of a specific data request for admins
func (h *DataRequestHandler) GetAdminRequestDetails(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := mux.Vars(r)["id"]
	var req models.DSRRequest
	if err := h.DB.Where("id = ?", id).First(&req).Error; err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

// ApproveRequest approves a data request
func (h *DataRequestHandler) ApproveRequest(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := mux.Vars(r)["id"]
	var req models.DSRRequest
	if err := h.DB.Where("id = ? AND status = ?", id, "Pending").
		First(&req).Error; err != nil {
		writeError(w, http.StatusNotFound, "request not found or already processed")
		return
	}
	req.Status = "Approved"
	req.ResolutionNote = "Request approved by " + claims.AdminID
	if err := h.DB.Save(&req).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update request")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

// RejectRequest rejects a data request
func (h *DataRequestHandler) RejectRequest(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := mux.Vars(r)["id"]
	var req models.DSRRequest
	if err := h.DB.Where("id = ? AND status = ?", id, "Pending").
		First(&req).Error; err != nil {
		writeError(w, http.StatusNotFound, "request not found or already processed")
		return
	}
	req.Status = "Rejected"
	req.ResolutionNote = "Request rejected by " + claims.AdminID
	if err := h.DB.Save(&req).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update request")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (h *DataRequestHandler) ListUserRequests(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAuthClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var requests []models.DSRRequest
	if err := h.DB.
		Where("user_id = ?", claims.UserID).
		Order("requested_at DESC").
		Find(&requests).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, requests)
}

func (h *DataRequestHandler) CreateUserRequest(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAuthClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		TenantID       string `json:"tenant_id"` // NEW: get from body, not JWT
		Type           string `json:"type"`
		CorrectionNote string `json:"correctionNote,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Type == "" || req.TenantID == "" {
		writeError(w, http.StatusBadRequest, "invalid request: missing tenant, type or invalid json")
		return
	}

	tenantUUID, err := uuid.Parse(req.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant_id")
		return
	}

	newRequest := models.DSRRequest{
		ID:          uuid.New(),
		UserID:      uuid.MustParse(claims.UserID),
		TenantID:    tenantUUID,
		Type:        req.Type,
		Status:      "Pending",
		RequestedAt: time.Now(),
	}
	if req.Type == "Data Correction" && req.CorrectionNote != "" {
		newRequest.ResolutionNote = req.CorrectionNote // or another field as needed
	}
	if err := h.DB.Create(&newRequest).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create request")
		return
	}
	writeJSON(w, http.StatusCreated, newRequest)
}

func (h *DataRequestHandler) GetRequestDetails(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAuthClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := mux.Vars(r)["id"]
	var req models.DSRRequest
	if err := h.DB.Where("id = ? AND user_id = ?", id, claims.UserID).First(&req).Error; err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, req)
}
