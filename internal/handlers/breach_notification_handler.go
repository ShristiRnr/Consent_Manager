package handlers

import (
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/datatypes"
)

type BreachNotificationHandler struct {
	service      *services.BreachNotificationService
	AuditService *services.AuditService
}

func NewBreachNotificationHandler(service *services.BreachNotificationService, auditService *services.AuditService) *BreachNotificationHandler {
	return &BreachNotificationHandler{service: service, AuditService: auditService}
}

func (h *BreachNotificationHandler) CreateBreachNotification(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusForbidden, "fiduciary access required")
		return
	}
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID in claims")
		return
	}

	var req dto.CreateBreachNotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	notification := &models.BreachNotification{
		TenantID:           tenantID,
		Description:        req.Description,
		BreachDate:         req.BreachDate,
		DetectionDate:      req.DetectionDate,
		AffectedUsersCount: req.AffectedUsersCount,
		Status:             req.Status,
	}

	if err := h.service.CreateBreachNotification(notification); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for breach notification creation
	if h.AuditService != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "breach_notification_created", "created", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"breach_notification_id": notification.ID.String(),
			"breach_type":            notification.BreachType,
			"severity":               notification.Severity,
			"affected_users_count":   notification.AffectedUsersCount,
		})
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(notification)
}

func (h *BreachNotificationHandler) GetBreachNotification(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	notificationID, err := uuid.Parse(vars["notificationId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid notification ID")
		return
	}

	notification, err := h.service.GetBreachNotificationByID(notificationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for breach notification access
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		tenantID, _ := uuid.Parse(claims.TenantID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "breach_notification_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"breach_notification_id": notification.ID.String(),
			"breach_type":            notification.BreachType,
			"severity":               notification.Severity,
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notification)
}

func (h *BreachNotificationHandler) ListBreachNotifications(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusForbidden, "fiduciary access required")
		return
	}
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID in claims")
		return
	}

	notifications, err := h.service.ListBreachNotifications(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for breach notification list access
	if h.AuditService != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "breach_notification_list_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"notifications_count": len(notifications),
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notifications)
}

func (h *BreachNotificationHandler) UpdateBreachNotification(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusForbidden, "fiduciary access required")
		return
	}

	vars := mux.Vars(r)
	notificationID, err := uuid.Parse(vars["notificationId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}

	var request dto.UpdateBreachNotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get existing notification to verify ownership
	existingNotification, err := h.service.GetByID(notificationID)
	if err != nil {
		writeError(w, http.StatusNotFound, "breach notification not found")
		return
	}

	if existingNotification.TenantID != tenantID {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// Convert string fields to JSON
	var remedialActionsJSON datatypes.JSON
	var preventiveMeasuresJSON datatypes.JSON
	
	if request.RemedialActions != "" {
		remedialActionsJSON = datatypes.JSON([]byte(`["` + request.RemedialActions + `"]`))
	}
	
	if request.PreventiveMeasures != "" {
		preventiveMeasuresJSON = datatypes.JSON([]byte(`["` + request.PreventiveMeasures + `"]`))
	}

	// Update the notification
	updatedNotification := &models.BreachNotification{
		ID:                   notificationID,
		TenantID:             tenantID,
		Description:          request.Description,
		BreachDate:           request.BreachDate,
		DetectionDate:        request.DetectionDate,
		AffectedUsersCount:   request.AffectedUsersCount,
		Severity:             request.Severity,
		BreachType:           request.BreachType,
		Status:               request.Status,
		RequiresDPBReporting: request.RequiresDPBReporting,
		RemedialActions:      remedialActionsJSON,
		PreventiveMeasures:   preventiveMeasuresJSON,
	}

	if err := h.service.Update(updatedNotification); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update breach notification")
		return
	}

	// Audit logging
	if h.AuditService != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, notificationID, "breach_notification_updated", "updated", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"notification_id": notificationID,
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(updatedNotification)
}

func (h *BreachNotificationHandler) DeleteBreachNotification(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusForbidden, "fiduciary access required")
		return
	}

	vars := mux.Vars(r)
	notificationID, err := uuid.Parse(vars["notificationId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid notification ID")
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}

	// Get existing notification to verify ownership
	existingNotification, err := h.service.GetByID(notificationID)
	if err != nil {
		writeError(w, http.StatusNotFound, "breach notification not found")
		return
	}

	if existingNotification.TenantID != tenantID {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	if err := h.service.Delete(notificationID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete breach notification")
		return
	}

	// Audit logging
	if h.AuditService != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, notificationID, "breach_notification_deleted", "deleted", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"notification_id": notificationID,
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *BreachNotificationHandler) GetBreachStats(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusForbidden, "fiduciary access required")
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}

	stats, err := h.service.GetStatsByTenant(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get breach statistics")
		return
	}

	// Audit logging
	if h.AuditService != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "breach_stats_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"total_breaches": stats["total"],
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
