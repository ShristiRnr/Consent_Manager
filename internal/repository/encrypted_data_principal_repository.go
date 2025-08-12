package repository

import (
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/encryption"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EncryptedDataPrincipalRepository struct {
	db *gorm.DB
}

func NewEncryptedDataPrincipalRepository(db *gorm.DB) *EncryptedDataPrincipalRepository {
	return &EncryptedDataPrincipalRepository{db: db}
}

func (r *EncryptedDataPrincipalRepository) GetDataPrincipalByID(id uuid.UUID) (*models.DataPrincipal, error) {
	var encryptedDP models.EncryptedDataPrincipal
	if err := r.db.First(&encryptedDP, "id = ?", id).Error; err != nil {
		return nil, err
	}
	
	return r.decryptDataPrincipal(&encryptedDP)
}

func (r *EncryptedDataPrincipalRepository) GetDataPrincipalByEmail(email string) (*models.DataPrincipal, error) {
	var encryptedDP models.EncryptedDataPrincipal
	if err := r.db.First(&encryptedDP, "email = ?", email).Error; err != nil {
		return nil, err
	}
	
	return r.decryptDataPrincipal(&encryptedDP)
}

func (r *EncryptedDataPrincipalRepository) CreateDataPrincipal(dp *models.DataPrincipal) error {
	encryptedDP, err := r.encryptDataPrincipal(dp)
	if err != nil {
		return err
	}
	
	return r.db.Create(encryptedDP).Error
}

func (r *EncryptedDataPrincipalRepository) UpdateDataPrincipal(dp *models.DataPrincipal) error {
	encryptedDP, err := r.encryptDataPrincipal(dp)
	if err != nil {
		return err
	}
	
	return r.db.Save(encryptedDP).Error
}

func (r *EncryptedDataPrincipalRepository) DeleteDataPrincipal(id uuid.UUID) error {
	return r.db.Delete(&models.EncryptedDataPrincipal{}, "id = ?", id).Error
}

func (r *EncryptedDataPrincipalRepository) encryptDataPrincipal(dp *models.DataPrincipal) (*models.EncryptedDataPrincipal, error) {
	encryptedDP := &models.EncryptedDataPrincipal{
		ID:                         dp.ID,
		TenantID:                   dp.TenantID,
		ExternalID:                 dp.ExternalID,
		Age:                        dp.Age,
		Location:                   dp.Location,
		IsVerified:                 dp.IsVerified,
		VerificationExpiry:         dp.VerificationExpiry,
		IsGuardianVerified:         dp.IsGuardianVerified,
		GuardianVerificationExpiry: dp.GuardianVerificationExpiry,
		CreatedAt:                  dp.CreatedAt,
		UpdatedAt:                  dp.UpdatedAt,
	}
	
	// Encrypt sensitive fields
	if err := r.encryptStringField(dp.Email, &encryptedDP.Email); err != nil {
		return nil, err
	}
	if err := r.encryptStringField(dp.Phone, &encryptedDP.Phone); err != nil {
		return nil, err
	}
	if err := r.encryptStringField(dp.FirstName, &encryptedDP.FirstName); err != nil {
		return nil, err
	}
	if err := r.encryptStringField(dp.LastName, &encryptedDP.LastName); err != nil {
		return nil, err
	}
	if err := r.encryptStringField(dp.VerificationToken, &encryptedDP.VerificationToken); err != nil {
		return nil, err
	}
	if err := r.encryptStringField(dp.GuardianEmail, &encryptedDP.GuardianEmail); err != nil {
		return nil, err
	}
	if err := r.encryptStringField(dp.GuardianVerificationToken, &encryptedDP.GuardianVerificationToken); err != nil {
		return nil, err
	}
	
	return encryptedDP, nil
}

func (r *EncryptedDataPrincipalRepository) decryptDataPrincipal(encryptedDP *models.EncryptedDataPrincipal) (*models.DataPrincipal, error) {
	dp := &models.DataPrincipal{
		ID:                         encryptedDP.ID,
		TenantID:                   encryptedDP.TenantID,
		ExternalID:                 encryptedDP.ExternalID,
		Age:                        encryptedDP.Age,
		Location:                   encryptedDP.Location,
		IsVerified:                 encryptedDP.IsVerified,
		VerificationExpiry:         encryptedDP.VerificationExpiry,
		IsGuardianVerified:         encryptedDP.IsGuardianVerified,
		GuardianVerificationExpiry: encryptedDP.GuardianVerificationExpiry,
		CreatedAt:                  encryptedDP.CreatedAt,
		UpdatedAt:                  encryptedDP.UpdatedAt,
	}
	
	// Decrypt sensitive fields
	var err error
	if dp.Email, err = r.decryptStringField(encryptedDP.Email); err != nil {
		return nil, err
	}
	if dp.Phone, err = r.decryptStringField(encryptedDP.Phone); err != nil {
		return nil, err
	}
	if dp.FirstName, err = r.decryptStringField(encryptedDP.FirstName); err != nil {
		return nil, err
	}
	if dp.LastName, err = r.decryptStringField(encryptedDP.LastName); err != nil {
		return nil, err
	}
	if dp.VerificationToken, err = r.decryptStringField(encryptedDP.VerificationToken); err != nil {
		return nil, err
	}
	if dp.GuardianEmail, err = r.decryptStringField(encryptedDP.GuardianEmail); err != nil {
		return nil, err
	}
	if dp.GuardianVerificationToken, err = r.decryptStringField(encryptedDP.GuardianVerificationToken); err != nil {
		return nil, err
	}
	
	return dp, nil
}

func (r *EncryptedDataPrincipalRepository) encryptStringField(plaintext string, encryptedField *string) error {
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

func (r *EncryptedDataPrincipalRepository) decryptStringField(encryptedText string) (string, error) {
	if encryptedText == "" {
		return "", nil
	}
	
	plaintext, err := encryption.Decrypt(encryptedText)
	if err != nil {
		return "", err
	}
	return plaintext, nil
}
