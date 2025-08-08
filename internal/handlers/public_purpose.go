package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/encryption"
	"consultrnr/consent-manager/pkg/log"
)

// Helper to securely resolve tenant ID from API key, using encryption-based scheme
func resolveTenantIDFromAPIKeyP(apiKey string) (uuid.UUID, error) {
	lookupHash, err := encryption.DeterministicEncrypt(apiKey)
	if err != nil {
		return uuid.Nil, err
	}
	var key models.APIKey
	// Only allow active keys
	if err := db.MasterDB.
		Where("hashed_key = ? AND revoked = false", lookupHash).
		First(&key).Error; err != nil {
		return uuid.Nil, err
	}
	// verify the key matches the raw API key
	if key.HashedKey != lookupHash {
		log.Logger.Error().Msgf("API key mismatch: %s != %s", key.HashedKey, lookupHash)
		return uuid.Nil, nil
	}
	return key.TenantID, nil
}

func GetPurposes(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		http.Error(w, "missing API key", http.StatusUnauthorized)
		return
	}

	tenantID, err := resolveTenantIDFromAPIKeyP(apiKey)
	if err != nil || tenantID == uuid.Nil {
		log.Logger.Error().Msgf("Invalid API key, resolveTenantIDFromAPIKeyP error: %v", err)
		http.Error(w, "invalid API key", http.StatusUnauthorized)
		return
	}

	schema := "tenant_" + tenantID.String()[:8]
	dbTenant, err := db.GetTenantDB(schema)
	if err != nil {
		log.Logger.Error().Err(err).Msg("Failed to get tenant DB")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var purposes []models.Purpose
	if err := dbTenant.Where("active = true").Find(&purposes).Error; err != nil {
		log.Logger.Error().Err(err).Msg("Failed to fetch purposes")
		http.Error(w, "failed to fetch purposes", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(purposes); err != nil {
		log.Logger.Error().Err(err).Msg("Failed to write response")
	}
}
