package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/jwtlink"
)

type PartnerConsentResponse struct {
	UserID   string          `json:"userId"`
	Consents map[string]bool `json:"consents"`
}

func PartnerGetConsentsHandler(w http.ResponseWriter, r *http.Request) {
	// scope check
	if !middlewares.HasScope(r, "read:consents") {
		http.Error(w, "forbidden - missing scope", http.StatusForbidden)
		return
	}

	// userId query
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		http.Error(w, "missing userId", http.StatusBadRequest)
		return
	}

	// auth header & token parse
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}
	token := parts[1]
	claims, err := jwtlink.ParseReviewToken(token)
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	// tenant DB
	schema := "tenant_" + claims.TenantID[:8]
	dbTenant, err := db.GetTenantDB(schema)
	if err != nil {
		http.Error(w, "tenant DB error", http.StatusInternalServerError)
		return
	}

	// fetch consents
	var consents []models.Consent
	if err := dbTenant.Where("uid = ?", userID).Find(&consents).Error; err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// build response
	result := PartnerConsentResponse{
		UserID:   userID,
		Consents: make(map[string]bool),
	}
	for _, c := range consents {
		var purposes []models.PurposeStatus

		// marshal the struct into JSON bytes, then unmarshal into our slice
		data, err := json.Marshal(c.Purposes)
		if err != nil {
			continue
		}
		if err := json.Unmarshal(data, &purposes); err != nil {
			continue
		}

		for _, p := range purposes {
			result.Consents[p.Name] = p.Status
		}
	}

	// write JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
