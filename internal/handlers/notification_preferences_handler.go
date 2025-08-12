package handlers

import (
	"encoding/json"
	"net/http"

	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"
	"github.com/google/uuid"
)

type NotificationPreferencesHandler struct {
	service *services.NotificationPreferencesService
}

func NewNotificationPreferencesHandler(service *services.NotificationPreferencesService) *NotificationPreferencesHandler {
	return &NotificationPreferencesHandler{service: service}
}

func (h *NotificationPreferencesHandler) Get(w http.ResponseWriter, r *http.Request) {
		userIDStr := middlewares.GetDataPrincipalID(r.Context())
	if userIDStr == "" {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusUnauthorized)
		return
	}

	preferences, err := h.service.Get(r.Context(), userID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(preferences)
}

func (h *NotificationPreferencesHandler) Update(w http.ResponseWriter, r *http.Request) {
		userIDStr := middlewares.GetDataPrincipalID(r.Context())
	if userIDStr == "" {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusUnauthorized)
		return
	}

	var preferences models.NotificationPreferences
	if err := json.NewDecoder(r.Body).Decode(&preferences); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	preferences.UserID = userID

	if err := h.service.Update(r.Context(), &preferences); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
