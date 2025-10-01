package handlers

import (
	"consultrnr/consent-manager/pkg/log"
	"encoding/json"
	"net/http"
)

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Logger.Error().Err(err).Msg("Error encoding JSON response")
	}
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, message string) {
	response := map[string]string{"error": message}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Logger.Error().Err(err).Msg("Error encoding error response")
	}
}
