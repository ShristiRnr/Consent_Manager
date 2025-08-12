package repository

import (
	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserConsentRepository struct {
	db *gorm.DB
}

func NewUserConsentRepository(db *gorm.DB) *UserConsentRepository {
	return &UserConsentRepository{db: db}
}

func (r *UserConsentRepository) CreateUserConsent(userConsent *models.UserConsent) (*models.UserConsent, error) {
	if err := r.db.Create(userConsent).Error; err != nil {
		return nil, err
	}
	return userConsent, nil
}

func (r *UserConsentRepository) UpdateUserConsent(userConsent *models.UserConsent) (*models.UserConsent, error) {
	if err := r.db.Save(userConsent).Error; err != nil {
		return nil, err
	}
	return userConsent, nil
}

func (r *UserConsentRepository) GetUserConsent(userID, purposeID, tenantID uuid.UUID) (*models.UserConsent, error) {
	var userConsent models.UserConsent
	if err := r.db.Where("user_id = ? AND purpose_id = ? AND tenant_id = ?", userID, purposeID, tenantID).First(&userConsent).Error; err != nil {
		return nil, err
	}
	return &userConsent, nil
}

func (r *UserConsentRepository) ListUserConsents(userID, tenantID uuid.UUID) ([]models.UserConsent, error) {
	var userConsents []models.UserConsent
	if err := r.db.Where("user_id = ? AND tenant_id = ?", userID, tenantID).Find(&userConsents).Error; err != nil {
		return nil, err
	}
	return userConsents, nil
}