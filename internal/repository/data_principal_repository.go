package repository

import (
	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type DataPrincipalRepository struct {
	db *gorm.DB
	encryptedRepo *EncryptedDataPrincipalRepository
}

func NewDataPrincipalRepository(db *gorm.DB) *DataPrincipalRepository {
	return &DataPrincipalRepository{db: db, encryptedRepo: NewEncryptedDataPrincipalRepository(db)}
}

func (r *DataPrincipalRepository) GetDataPrincipalByID(id uuid.UUID) (*models.DataPrincipal, error) {
	return r.encryptedRepo.GetDataPrincipalByID(id)
}

func (r *DataPrincipalRepository) GetDataPrincipalByEmail(email string) (*models.DataPrincipal, error) {
	return r.encryptedRepo.GetDataPrincipalByEmail(email)
}

func (r *DataPrincipalRepository) CreateDataPrincipal(dp *models.DataPrincipal) error {
	return r.encryptedRepo.CreateDataPrincipal(dp)
}

func (r *DataPrincipalRepository) UpdateDataPrincipal(dp *models.DataPrincipal) error {
	return r.encryptedRepo.UpdateDataPrincipal(dp)
}

func (r *DataPrincipalRepository) DeleteDataPrincipal(id uuid.UUID) error {
	return r.encryptedRepo.DeleteDataPrincipal(id)
}
