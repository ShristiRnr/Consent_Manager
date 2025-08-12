package repository

import (
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/encryption"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EncryptedBreachNotificationRepository struct {
	db *gorm.DB
}

func NewEncryptedBreachNotificationRepository(db *gorm.DB) *EncryptedBreachNotificationRepository {
	return &EncryptedBreachNotificationRepository{db: db}
}

func (r *EncryptedBreachNotificationRepository) CreateBreachNotification(breach *models.BreachNotification) error {
	encryptedBreach, err := r.encryptBreachNotification(breach)
	if err != nil {
		return err
	}
	return r.db.Create(encryptedBreach).Error
}

func (r *EncryptedBreachNotificationRepository) GetBreachNotificationByID(id uuid.UUID) (*models.BreachNotification, error) {
	var encryptedBreach models.EncryptedBreachNotification
	if err := r.db.First(&encryptedBreach, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return r.decryptBreachNotification(&encryptedBreach)
}

func (r *EncryptedBreachNotificationRepository) UpdateBreachNotification(breach *models.BreachNotification) error {
	encryptedBreach, err := r.encryptBreachNotification(breach)
	if err != nil {
		return err
	}
	return r.db.Save(encryptedBreach).Error
}

func (r *EncryptedBreachNotificationRepository) DeleteBreachNotification(id uuid.UUID) error {
	return r.db.Delete(&models.EncryptedBreachNotification{}, "id = ?", id).Error
}

func (r *EncryptedBreachNotificationRepository) ListBreachNotifications() ([]models.BreachNotification, error) {
	var encryptedBreaches []models.EncryptedBreachNotification
	if err := r.db.Find(&encryptedBreaches).Error; err != nil {
		return nil, err
	}

	var breaches []models.BreachNotification
	for _, encryptedBreach := range encryptedBreaches {
		breach, err := r.decryptBreachNotification(&encryptedBreach)
		if err != nil {
			return nil, err
		}
		breaches = append(breaches, *breach)
	}
	return breaches, nil
}

func (r *EncryptedBreachNotificationRepository) GetBreachNotificationsByTenant(tenantID uuid.UUID) ([]models.BreachNotification, error) {
	var encryptedBreaches []models.EncryptedBreachNotification
	if err := r.db.Where("tenant_id = ?", tenantID).Find(&encryptedBreaches).Error; err != nil {
		return nil, err
	}

	var breaches []models.BreachNotification
	for _, encryptedBreach := range encryptedBreaches {
		breach, err := r.decryptBreachNotification(&encryptedBreach)
		if err != nil {
			return nil, err
		}
		breaches = append(breaches, *breach)
	}
	return breaches, nil
}

func (r *EncryptedBreachNotificationRepository) encryptBreachNotification(breach *models.BreachNotification) (*models.EncryptedBreachNotification, error) {
	encryptedBreach := &models.EncryptedBreachNotification{
		ID:                   breach.ID,
		TenantID:             breach.TenantID,
		BreachDate:           breach.BreachDate,
		DetectionDate:        breach.DetectionDate,
		NotificationDate:     breach.NotificationDate,
		AffectedUsersCount:   breach.AffectedUsersCount,
		NotifiedUsersCount:   breach.NotifiedUsersCount,
		Severity:             breach.Severity,
		BreachType:           breach.BreachType,
		Status:               breach.Status,
		RequiresDPBReporting: breach.RequiresDPBReporting,
		DPBReported:          breach.DPBReported,
		DPBReportedDate:      breach.DPBReportedDate,
		DPBReportReference:   breach.DPBReportReference,
		RemedialActions:      breach.RemedialActions,
		PreventiveMeasures:   breach.PreventiveMeasures,
		InvestigationDate:    breach.InvestigationDate,
		ComplianceStatus:     breach.ComplianceStatus,
		CreatedAt:            breach.CreatedAt,
		UpdatedAt:            breach.UpdatedAt,
	}

	// Encrypt sensitive fields
	if err := r.encryptStringField(breach.Description, &encryptedBreach.Description); err != nil {
		return nil, err
	}

	if err := r.encryptStringFieldPtr(breach.InvestigationSummary, &encryptedBreach.InvestigationSummary); err != nil {
		return nil, err
	}

	if err := r.encryptStringFieldPtr(breach.InvestigatedBy, &encryptedBreach.InvestigatedBy); err != nil {
		return nil, err
	}

	if err := r.encryptStringFieldPtr(breach.ComplianceNotes, &encryptedBreach.ComplianceNotes); err != nil {
		return nil, err
	}

	return encryptedBreach, nil
}

func (r *EncryptedBreachNotificationRepository) decryptBreachNotification(encryptedBreach *models.EncryptedBreachNotification) (*models.BreachNotification, error) {
	breach := &models.BreachNotification{
		ID:                   encryptedBreach.ID,
		TenantID:             encryptedBreach.TenantID,
		BreachDate:           encryptedBreach.BreachDate,
		DetectionDate:        encryptedBreach.DetectionDate,
		NotificationDate:     encryptedBreach.NotificationDate,
		AffectedUsersCount:   encryptedBreach.AffectedUsersCount,
		NotifiedUsersCount:   encryptedBreach.NotifiedUsersCount,
		Severity:             encryptedBreach.Severity,
		BreachType:           encryptedBreach.BreachType,
		Status:               encryptedBreach.Status,
		RequiresDPBReporting: encryptedBreach.RequiresDPBReporting,
		DPBReported:          encryptedBreach.DPBReported,
		DPBReportedDate:      encryptedBreach.DPBReportedDate,
		DPBReportReference:   encryptedBreach.DPBReportReference,
		RemedialActions:      encryptedBreach.RemedialActions,
		PreventiveMeasures:   encryptedBreach.PreventiveMeasures,
		InvestigationDate:    encryptedBreach.InvestigationDate,
		ComplianceStatus:     encryptedBreach.ComplianceStatus,
		CreatedAt:            encryptedBreach.CreatedAt,
		UpdatedAt:            encryptedBreach.UpdatedAt,
	}

	// Decrypt sensitive fields
	var err error
	if breach.Description, err = r.decryptStringField(encryptedBreach.Description); err != nil {
		return nil, err
	}

	if breach.InvestigationSummary, err = r.decryptStringFieldPtr(encryptedBreach.InvestigationSummary); err != nil {
		return nil, err
	}

	if breach.InvestigatedBy, err = r.decryptStringFieldPtr(encryptedBreach.InvestigatedBy); err != nil {
		return nil, err
	}

	if breach.ComplianceNotes, err = r.decryptStringFieldPtr(encryptedBreach.ComplianceNotes); err != nil {
		return nil, err
	}

	return breach, nil
}

func (r *EncryptedBreachNotificationRepository) encryptStringField(plaintext string, encryptedField *string) error {
	if plaintext == "" {
		*encryptedField = ""
		return nil
	}

	encrypted, err := encryption.Encrypt(plaintext)
	if err != nil {
		return err
	}
	*encryptedField = encrypted
	return nil
}

func (r *EncryptedBreachNotificationRepository) encryptStringFieldPtr(plaintext *string, encryptedField **string) error {
	if plaintext == nil {
		*encryptedField = nil
		return nil
	}

	encrypted, err := encryption.Encrypt(*plaintext)
	if err != nil {
		return err
	}
	*encryptedField = &encrypted
	return nil
}

func (r *EncryptedBreachNotificationRepository) decryptStringField(encryptedText string) (string, error) {
	if encryptedText == "" {
		return "", nil
	}

	plaintext, err := encryption.Decrypt(encryptedText)
	if err != nil {
		return "", err
	}
	return plaintext, nil
}

func (r *EncryptedBreachNotificationRepository) decryptStringFieldPtr(encryptedText *string) (*string, error) {
	if encryptedText == nil {
		return nil, nil
	}

	plaintext, err := encryption.Decrypt(*encryptedText)
	if err != nil {
		return nil, err
	}
	return &plaintext, nil
}
