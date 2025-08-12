package unit

import (
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/models"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MockConsentRepository is a mock implementation of the ConsentRepository interface
type MockConsentRepository struct {
	consents  map[uuid.UUID]models.Consent
	histories map[uuid.UUID][]models.ConsentHistory
}

// NewMockConsentRepository creates a new mock consent repository
func NewMockConsentRepository() *MockConsentRepository {
	return &MockConsentRepository{
		consents:  make(map[uuid.UUID]models.Consent),
		histories: make(map[uuid.UUID][]models.ConsentHistory),
	}
}

// UpsertConsent implements the ConsentRepository interface
func (m *MockConsentRepository) UpsertConsent(consent *models.Consent) error {
	m.consents[consent.ID] = *consent
	return nil
}

// GetUserConsentInTenant implements the ConsentRepository interface
func (m *MockConsentRepository) GetUserConsentInTenant(tenantDB *gorm.DB, tenantID, userID uuid.UUID) (*models.Consent, error) {
	for _, consent := range m.consents {
		if consent.UserID == userID && consent.TenantID == tenantID {
			return &consent, nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

// DB implements the ConsentRepository interface
func (m *MockConsentRepository) DB() *gorm.DB {
	return nil
}

// CreateHistory implements the ConsentRepository interface
func (m *MockConsentRepository) CreateHistory(h *models.ConsentHistory, tenantID uuid.UUID) error {
	m.histories[h.UserID] = append(m.histories[h.UserID], *h)
	return nil
}

// GetPurposesByTenant implements the ConsentRepository interface
func (m *MockConsentRepository) GetPurposesByTenant(tenantID uuid.UUID) (dto.ConsentPurposes, error) {
	for _, consent := range m.consents {
		if consent.TenantID == tenantID {
			return consent.Purposes, nil
		}
	}
	return dto.ConsentPurposes{}, errors.New("no consent found for tenant")
}

// GetAllConsentsByTenant implements the ConsentRepository interface
func (m *MockConsentRepository) GetAllConsentsByTenant(tenantDB *gorm.DB, tenantID uuid.UUID) ([]models.Consent, error) {
	var consents []models.Consent
	for _, consent := range m.consents {
		if consent.TenantID == tenantID {
			consents = append(consents, consent)
		}
	}
	return consents, nil
}

// GetConsentHistory implements the ConsentRepository interface
func (m *MockConsentRepository) GetConsentHistory(uid, consentID string) ([]models.ConsentHistory, error) {
	userID, err := uuid.Parse(uid)
	if err != nil {
		return nil, err
	}
	if history, exists := m.histories[userID]; exists {
		return history, nil
	}
	return nil, errors.New("no history found")
}

// AddConsent adds a consent to the mock repository for testing
func (m *MockConsentRepository) AddConsent(consent models.Consent) {
	m.consents[consent.ID] = consent
}

// GetConsents returns all consents in the mock repository
func (m *MockConsentRepository) GetConsents() map[uuid.UUID]models.Consent {
	return m.consents
}
