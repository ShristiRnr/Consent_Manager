package repository

import (
	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ConsentFormRepository struct {
	db *gorm.DB
}

func NewConsentFormRepository(db *gorm.DB) *ConsentFormRepository {
	return &ConsentFormRepository{db: db}
}

func (r *ConsentFormRepository) CreateConsentForm(form *models.ConsentForm) (*models.ConsentForm, error) {
	if err := r.db.Create(form).Error; err != nil {
		return nil, err
	}
	return form, nil
}

func (r *ConsentFormRepository) UpdateConsentForm(form *models.ConsentForm) (*models.ConsentForm, error) {
	if err := r.db.Save(form).Error; err != nil {
		return nil, err
	}
	return form, nil
}

func (r *ConsentFormRepository) DeleteConsentForm(formID uuid.UUID) error {
	return r.db.Delete(&models.ConsentForm{}, formID).Error
}

func (r *ConsentFormRepository) GetConsentFormByID(formID uuid.UUID) (*models.ConsentForm, error) {
	var form models.ConsentForm
	if err := r.db.Preload("Purposes").Preload("Purposes.Purpose").First(&form, formID).Error; err != nil {
		return nil, err
	}
	return &form, nil
}

func (r *ConsentFormRepository) ListConsentForms(tenantID uuid.UUID) ([]models.ConsentForm, error) {
	var forms []models.ConsentForm
	if err := r.db.Where("tenant_id = ?", tenantID).Find(&forms).Error; err != nil {
		return nil, err
	}
	return forms, nil
}

func (r *ConsentFormRepository) AddPurposeToConsentForm(formID, purposeID uuid.UUID, dataObjects, vendorIDs []string, expiryInDays int) (*models.ConsentFormPurpose, error) {
	formPurpose := &models.ConsentFormPurpose{
		ID:            uuid.New(),
		ConsentFormID: formID,
		PurposeID:     purposeID,
		DataObjects:   dataObjects,
		VendorIDs:     vendorIDs,
		ExpiryInDays:  expiryInDays,
	}
	if err := r.db.Create(formPurpose).Error; err != nil {
		return nil, err
	}
	return formPurpose, nil
}

func (r *ConsentFormRepository) UpdatePurposeInConsentForm(formID, purposeID uuid.UUID, dataObjects, vendorIDs []string, expiryInDays int) (*models.ConsentFormPurpose, error) {
	var formPurpose models.ConsentFormPurpose
	if err := r.db.Where("consent_form_id = ? AND purpose_id = ?", formID, purposeID).First(&formPurpose).Error; err != nil {
		return nil, err
	}

	formPurpose.DataObjects = dataObjects
	formPurpose.VendorIDs = vendorIDs
	formPurpose.ExpiryInDays = expiryInDays

	if err := r.db.Save(&formPurpose).Error; err != nil {
		return nil, err
	}
	return &formPurpose, nil
}

func (r *ConsentFormRepository) RemovePurposeFromConsentForm(formID, purposeID uuid.UUID) error {
	return r.db.Where("consent_form_id = ? AND purpose_id = ?", formID, purposeID).Delete(&models.ConsentFormPurpose{}).Error
}

func (r *ConsentFormRepository) GetConsentFormPurpose(formID, purposeID uuid.UUID) (*models.ConsentFormPurpose, error) {
	var formPurpose models.ConsentFormPurpose
	if err := r.db.Where("consent_form_id = ? AND purpose_id = ?").First(&formPurpose).Error; err != nil {
		return nil, err
	}
	return &formPurpose, nil
}

func (r *ConsentFormRepository) PublishConsentForm(formID uuid.UUID) error {
	return r.db.Model(&models.ConsentForm{}).Where("id = ?", formID).Update("published", true).Error
}