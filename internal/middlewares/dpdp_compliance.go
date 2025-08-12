package middlewares

import (
	"encoding/json"
	"net/http"

	"consultrnr/consent-manager/internal/compliance"
	"consultrnr/consent-manager/internal/models"
)

// DPDPComplianceMiddleware checks if requests meet DPDP compliance requirements
func DPDPComplianceMiddleware() func(http.Handler) http.Handler {
	validator := compliance.NewDPDPComplianceValidator()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only apply to specific endpoints that create/update compliance-related data
			switch r.URL.Path {
			case "/api/v1/consent-forms": // POST requests for creating consent forms
				if r.Method == http.MethodPost {
					var form models.ConsentForm
					if err := json.NewDecoder(r.Body).Decode(&form); err == nil {
						violations := validator.ValidateConsentForm(&form)
						if len(violations) > 0 {
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(http.StatusBadRequest)
							json.NewEncoder(w).Encode(map[string]interface{}{
								"error": "DPDP compliance violations",
								"violations": violations,
							})
							return
						}
					}
				}
			case "/api/v1/purposes": // POST requests for creating purposes
				if r.Method == http.MethodPost {
					var purpose models.Purpose
					if err := json.NewDecoder(r.Body).Decode(&purpose); err == nil {
						violations := validator.ValidatePurpose(&purpose)
						if len(violations) > 0 {
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(http.StatusBadRequest)
							json.NewEncoder(w).Encode(map[string]interface{}{
								"error": "DPDP compliance violations",
								"violations": violations,
							})
							return
						}
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
