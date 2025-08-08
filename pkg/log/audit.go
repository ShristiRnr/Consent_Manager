package log

import (
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/audit"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

type ConsentAuditParams struct {
	UserID        uuid.UUID
	TenantID      uuid.UUID
	PurposeID     uuid.UUID
	ActionType    string
	ConsentStatus string
	Initiator     string // "user" or "system"
	SourceIP      string
}

// AuditConsent creates and logs an immutable consent audit record.
func AuditConsent(db *gorm.DB, params ConsentAuditParams) {
	now := time.Now().UTC()
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		params.UserID, params.PurposeID, params.ActionType,
		params.ConsentStatus, params.Initiator, params.SourceIP,
		now.Format(time.RFC3339),
	)

	entry := models.AuditLog{
		LogID:         uuid.New(),
		UserID:        params.UserID,
		TenantID:      params.TenantID,
		PurposeID:     params.PurposeID,
		ActionType:    params.ActionType,
		ConsentStatus: params.ConsentStatus,
		Initiator:     params.Initiator,
		SourceIP:      params.SourceIP,
		Timestamp:     now,
		AuditHash:     audit.ComputeAuditHash(payload),
	}

	// Structured logging for traceability
	log.Info().
		Str("event", "consent_audit").
		Str("user_id", entry.UserID.String()).
		Str("tenant_id", entry.TenantID.String()).
		Str("purpose_id", entry.PurposeID.String()).
		Str("action", entry.ActionType).
		Str("status", entry.ConsentStatus).
		Str("initiator", entry.Initiator).
		Str("ip", entry.SourceIP).
		Str("audit_hash", entry.AuditHash).
		Msg("Consent action logged")

	if err := db.Create(&entry).Error; err != nil {
		log.Error().
			Err(err).
			Str("tenant_id", params.TenantID.String()).
			Msg("Failed to persist audit log")
	}
}
