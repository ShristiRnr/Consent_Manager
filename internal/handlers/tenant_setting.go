package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/jwtlink"
)

type UpdateTenantSettingsRequest struct {
	ReviewFrequencyMonths int `json:"reviewFrequencyMonths"`
}

func UpdateTenantSettingsHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auth header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "invalid Authorization header", http.StatusUnauthorized)
			return
		}

		// Parse token
		claims, err := jwtlink.ParseReviewToken(parts[1])
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		tenantID, err := uuid.Parse(claims.TenantID)
		if err != nil {
			http.Error(w, "invalid tenant ID format", http.StatusBadRequest)
			return
		}

		// Parse body
		var req UpdateTenantSettingsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.ReviewFrequencyMonths < 1 || req.ReviewFrequencyMonths > 12 {
			http.Error(w, "reviewFrequencyMonths must be between 1 and 12", http.StatusBadRequest)
			return
		}

		// Update DB
		if err := db.Model(&models.Tenant{}).
			Where("tenant_id = ?", tenantID).
			Update("review_frequency_months", req.ReviewFrequencyMonths).Error; err != nil {
			http.Error(w, "update failed", http.StatusInternalServerError)
			return
		}

		// Success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Review frequency updated successfully",
		})
	}
}
