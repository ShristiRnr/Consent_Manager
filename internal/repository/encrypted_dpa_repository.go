package repository

import (
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/encryption"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EncryptedDPARepository struct {
	db *gorm.DB
}

func NewEncryptedDPARepository(db *gorm.DB) *EncryptedDPARepository {
	return &EncryptedDPARepository{db: db}
}

func (r *EncryptedDPARepository) CreateDPA(dpa *models.DataProcessingAgreement) error {
	encryptedDPA, err := r.encryptDPA(dpa)
	if err != nil {
		return err
	}
	return r.db.Create(encryptedDPA).Error
}

func (r *EncryptedDPARepository) GetDPAByID(id uuid.UUID) (*models.DataProcessingAgreement, error) {
	var encryptedDPA models.EncryptedDataProcessingAgreement
	if err := r.db.First(&encryptedDPA, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return r.decryptDPA(&encryptedDPA)
}

func (r *EncryptedDPARepository) UpdateDPA(dpa *models.DataProcessingAgreement) error {
	encryptedDPA, err := r.encryptDPA(dpa)
	if err != nil {
		return err
	}
	return r.db.Save(encryptedDPA).Error
}

func (r *EncryptedDPARepository) DeleteDPA(id uuid.UUID) error {
	return r.db.Delete(&models.EncryptedDataProcessingAgreement{}, "id = ?", id).Error
}

func (r *EncryptedDPARepository) ListDPAs() ([]models.DataProcessingAgreement, error) {
	var encryptedDPAs []models.EncryptedDataProcessingAgreement
	if err := r.db.Find(&encryptedDPAs).Error; err != nil {
		return nil, err
	}

	var dpas []models.DataProcessingAgreement
	for _, encryptedDPA := range encryptedDPAs {
		dpa, err := r.decryptDPA(&encryptedDPA)
		if err != nil {
			return nil, err
		}
		dpas = append(dpas, *dpa)
	}
	return dpas, nil
}

func (r *EncryptedDPARepository) GetDPAsByVendor(vendorID uuid.UUID) ([]models.DataProcessingAgreement, error) {
	var encryptedDPAs []models.EncryptedDataProcessingAgreement
	if err := r.db.Where("vendor_id = ?", vendorID).Find(&encryptedDPAs).Error; err != nil {
		return nil, err
	}

	var dpas []models.DataProcessingAgreement
	for _, encryptedDPA := range encryptedDPAs {
		dpa, err := r.decryptDPA(&encryptedDPA)
		if err != nil {
			return nil, err
		}
		dpas = append(dpas, *dpa)
	}
	return dpas, nil
}

func (r *EncryptedDPARepository) GetDPAsByTenant(tenantID uuid.UUID) ([]models.DataProcessingAgreement, error) {
	var encryptedDPAs []models.EncryptedDataProcessingAgreement
	if err := r.db.Where("tenant_id = ?", tenantID).Find(&encryptedDPAs).Error; err != nil {
		return nil, err
	}

	var dpas []models.DataProcessingAgreement
	for _, encryptedDPA := range encryptedDPAs {
		dpa, err := r.decryptDPA(&encryptedDPA)
		if err != nil {
			return nil, err
		}
		dpas = append(dpas, *dpa)
	}
	return dpas, nil
}

func (r *EncryptedDPARepository) CreateComplianceCheck(check *models.DPAComplianceCheck) error {
	return r.db.Create(check).Error
}

func (r *EncryptedDPARepository) GetComplianceChecks(dpaID uuid.UUID) ([]models.DPAComplianceCheck, error) {
	var checks []models.DPAComplianceCheck
	if err := r.db.Where("dpa_id = ?", dpaID).Find(&checks).Error; err != nil {
		return nil, err
	}
	return checks, nil
}

func (r *EncryptedDPARepository) encryptDPA(dpa *models.DataProcessingAgreement) (*models.EncryptedDataProcessingAgreement, error) {
	encryptedDPA := &models.EncryptedDataProcessingAgreement{
		ID:                   dpa.ID,
		TenantID:             dpa.TenantID,
		VendorID:             dpa.VendorID,
		Status:               dpa.Status,
		EffectiveDate:        dpa.EffectiveDate,
		ExpiryDate:           dpa.ExpiryDate,
		ProcessingPurposes:   dpa.ProcessingPurposes,
		DataCategories:       dpa.DataCategories,
		ProcessingLocation:   dpa.ProcessingLocation,
		SubProcessingAllowed: dpa.SubProcessingAllowed,
		SecurityMeasures:     dpa.SecurityMeasures,
		DataRetentionPeriod:  dpa.DataRetentionPeriod,
		DataSubjectRights:    dpa.DataSubjectRights,
		BreachNotification:   dpa.BreachNotification,
		AuditRights:          dpa.AuditRights,
		LiabilityCap:         dpa.LiabilityCap,
		InsuranceCoverage:    dpa.InsuranceCoverage,
		GoverningLaw:         dpa.GoverningLaw,
		SignedDate:           dpa.SignedDate,
		TerminationDate:      dpa.TerminationDate,
		CreatedAt:            dpa.CreatedAt,
		UpdatedAt:            dpa.UpdatedAt,
		Version:              dpa.Version,
		PreviousVersionID:    dpa.PreviousVersionID,
	}

	// Encrypt sensitive fields
	if err := r.encryptStringField(dpa.AgreementTitle, &encryptedDPA.AgreementTitle); err != nil {
		return nil, err
	}
	if err := r.encryptStringField(dpa.AgreementNumber, &encryptedDPA.AgreementNumber); err != nil {
		return nil, err
	}
	if err := r.encryptStringField(dpa.SignatoryName, &encryptedDPA.SignatoryName); err != nil {
		return nil, err
	}
	if err := r.encryptStringField(dpa.SignatoryTitle, &encryptedDPA.SignatoryTitle); err != nil {
		return nil, err
	}

	// Encrypt signature if present
	if dpa.Signature != nil {
		encryptedSignature, err := encryption.Encrypt(*dpa.Signature)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt signature: %w", err)
		}
		encryptedDPA.Signature = &encryptedSignature
	}

	return encryptedDPA, nil
}

func (r *EncryptedDPARepository) decryptDPA(encryptedDPA *models.EncryptedDataProcessingAgreement) (*models.DataProcessingAgreement, error) {
	dpa := &models.DataProcessingAgreement{
		ID:                   encryptedDPA.ID,
		TenantID:             encryptedDPA.TenantID,
		VendorID:             encryptedDPA.VendorID,
		Status:               encryptedDPA.Status,
		EffectiveDate:        encryptedDPA.EffectiveDate,
		ExpiryDate:           encryptedDPA.ExpiryDate,
		ProcessingPurposes:   encryptedDPA.ProcessingPurposes,
		DataCategories:       encryptedDPA.DataCategories,
		ProcessingLocation:   encryptedDPA.ProcessingLocation,
		SubProcessingAllowed: encryptedDPA.SubProcessingAllowed,
		SecurityMeasures:     encryptedDPA.SecurityMeasures,
		DataRetentionPeriod:  encryptedDPA.DataRetentionPeriod,
		DataSubjectRights:    encryptedDPA.DataSubjectRights,
		BreachNotification:   encryptedDPA.BreachNotification,
		AuditRights:          encryptedDPA.AuditRights,
		LiabilityCap:         encryptedDPA.LiabilityCap,
		InsuranceCoverage:    encryptedDPA.InsuranceCoverage,
		GoverningLaw:         encryptedDPA.GoverningLaw,
		SignedDate:           encryptedDPA.SignedDate,
		TerminationDate:      encryptedDPA.TerminationDate,
		CreatedAt:            encryptedDPA.CreatedAt,
		UpdatedAt:            encryptedDPA.UpdatedAt,
		Version:              encryptedDPA.Version,
		PreviousVersionID:    encryptedDPA.PreviousVersionID,
	}

	// Decrypt sensitive fields
	var err error
	if dpa.AgreementTitle, err = r.decryptStringField(encryptedDPA.AgreementTitle); err != nil {
		return nil, err
	}
	if dpa.AgreementNumber, err = r.decryptStringField(encryptedDPA.AgreementNumber); err != nil {
		return nil, err
	}
	if dpa.SignatoryName, err = r.decryptStringField(encryptedDPA.SignatoryName); err != nil {
		return nil, err
	}
	if dpa.SignatoryTitle, err = r.decryptStringField(encryptedDPA.SignatoryTitle); err != nil {
		return nil, err
	}

	// Decrypt signature if present
	if encryptedDPA.Signature != nil {
		decryptedSignature, err := encryption.Decrypt(*encryptedDPA.Signature)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt signature: %w", err)
		}
		dpa.Signature = &decryptedSignature
	}

	return dpa, nil
}

func (r *EncryptedDPARepository) encryptStringField(plaintext string, encryptedField *string) error {
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

func (r *EncryptedDPARepository) decryptStringField(encryptedText string) (string, error) {
	if encryptedText == "" {
		return "", nil
	}

	plaintext, err := encryption.Decrypt(encryptedText)
	if err != nil {
		return "", err
	}
	return plaintext, nil
}
