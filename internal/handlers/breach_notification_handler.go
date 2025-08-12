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
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "breach_notification_list_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"notifications_count": len(notifications),
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notifications)
}
