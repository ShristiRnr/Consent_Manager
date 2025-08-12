package middlewares

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/localization"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// DataLocalizationMiddleware ensures data operations comply with Indian data localization requirements
func DataLocalizationMiddleware() func(http.Handler) http.Handler {
	cfg := config.LoadConfig()
	localizationService := localization.NewDataLocalizationService(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract tenant ID from request context or parameters
			vars := mux.Vars(r)
			
			// Check if this is a data operation that requires localization compliance
			switch r.URL.Path {
			case "/api/v1/consent", "/api/v1/consents": // Consent operations
				if r.Method == http.MethodPost || r.Method == http.MethodPut {
					// Extract tenant ID from request or context
					tenantID, err := extractTenantID(r, vars)
					if err != nil {
						writeError(w, http.StatusBadRequest, "Unable to determine tenant ID for data localization compliance check")
						return
					}

					// Check if data location is compliant
					isCompliant, message := localizationService.IsDataLocationCompliant(tenantID, db.GetMasterDB())
					if !isCompliant {
						writeError(w, http.StatusForbidden, message)
						return
					}
				}
			case "/api/v1/data-transfer": // Data transfer operations
				if r.Method == http.MethodPost {
					var transferRequest struct {
						SourceTenantID uuid.UUID `json:"sourceTenantId"`
						TargetTenantID uuid.UUID `json:"targetTenantId"`
					}
					
					if err := json.NewDecoder(r.Body).Decode(&transferRequest); err == nil {
						isCompliant, message := localizationService.ValidateDataTransfer(
							transferRequest.SourceTenantID, 
							transferRequest.TargetTenantID, 
							db.GetMasterDB(),
						)
						if !isCompliant {
							writeError(w, http.StatusForbidden, message)
							return
						}
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractTenantID extracts tenant ID from request context or parameters
func extractTenantID(r *http.Request, vars map[string]string) (uuid.UUID, error) {
	// First try to get tenant ID from context (set by auth middleware)
	if tenantIDStr, ok := r.Context().Value("tenant_id").(string); ok {
		return uuid.Parse(tenantIDStr)
	}

	// Try to get tenant ID from URL parameters
	if tenantIDStr, ok := vars["tenantId"]; ok {
		return uuid.Parse(tenantIDStr)
	}

	// Try to get tenant ID from request body for POST requests
	// This is a simplified example - in practice, you'd need to parse the body
	// without consuming it entirely
	return uuid.Nil, fmt.Errorf("unable to extract tenant ID from request")
}

// writeError writes a JSON error response
func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
