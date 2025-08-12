package unit

import (
	"consultrnr/consent-manager/internal/models"
	"context"

	"github.com/google/uuid"
)

// MockAuditService is a mock implementation of the AuditService
type MockAuditService struct {
	audits []interface{}
}

// NewMockAuditService creates a new mock audit service
func NewMockAuditService() *MockAuditService {
	return &MockAuditService{
		audits: make([]interface{}, 0),
	}
}

// Create implements the AuditService interface
func (m *MockAuditService) Create(ctx context.Context, userID, tenantID, purposeID uuid.UUID, actionType, consentStatus, initiator, sourceIP, geoRegion, jurisdiction string, details map[string]interface{}) error {
	// For testing purposes, we just store the audit record
	m.audits = append(m.audits, map[string]interface{}{
		"userID":        userID,
		"tenantID":      tenantID,
		"purposeID":     purposeID,
		"actionType":    actionType,
		"consentStatus": consentStatus,
		"initiator":     initiator,
		"sourceIP":      sourceIP,
		"geoRegion":     geoRegion,
		"jurisdiction":  jurisdiction,
		"details":       details,
	})
	return nil
}

// GetConsentAuditLogs implements the AuditService interface
func (m *MockAuditService) GetConsentAuditLogs(tenantID string) ([]models.AuditLog, error) {
	// For testing purposes, return empty slice
	return []models.AuditLog{}, nil
}

// GetAudits returns all audit records for testing
func (m *MockAuditService) GetAudits() []interface{} {
	return m.audits
}
