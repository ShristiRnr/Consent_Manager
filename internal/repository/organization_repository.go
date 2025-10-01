package repository

import (
	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type OrganizationRepository struct {
	db *gorm.DB
}

func NewOrganizationRepository(db *gorm.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

func (r *OrganizationRepository) Create(organization *models.OrganizationEntity) error {
	return r.db.Create(organization).Error
}

func (r *OrganizationRepository) Update(organization *models.OrganizationEntity) error {
	return r.db.Save(organization).Error
}

func (r *OrganizationRepository) Delete(id uuid.UUID) error {
	return r.db.Where("id = ?", id).Delete(&models.OrganizationEntity{}).Error
}

func (r *OrganizationRepository) List() ([]models.OrganizationEntity, error) {
	var organizations []models.OrganizationEntity
	if err := r.db.Find(&organizations).Error; err != nil {
		return nil, err
	}
	return organizations, nil
}

func (r *OrganizationRepository) GetByID(id uuid.UUID) (*models.OrganizationEntity, error) {
	var organization models.OrganizationEntity
	if err := r.db.Where("id = ?", id).First(&organization).Error; err != nil {
		return nil, err
	}
	return &organization, nil
}

func (r *OrganizationRepository) GetByName(name string) (*models.OrganizationEntity, error) {
	var organization models.OrganizationEntity
	if err := r.db.Where("name = ?", name).First(&organization).Error; err != nil {
		return nil, err
	}
	return &organization, nil
}

func (r *OrganizationRepository) GetByIndustry(industry string) ([]models.OrganizationEntity, error) {
	var organizations []models.OrganizationEntity
	if err := r.db.Where("industry = ?", industry).Find(&organizations).Error; err != nil {
		return nil, err
	}
	return organizations, nil
}
