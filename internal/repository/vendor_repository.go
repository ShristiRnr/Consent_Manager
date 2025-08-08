package repository

import (
	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type VendorRepository interface {
	Create(vendor *models.Vendor) error
	Update(vendor *models.Vendor) error
	Delete(id uuid.UUID) error
	GetByID(id uuid.UUID) (*models.Vendor, error)
	List(offset, limit int) ([]models.Vendor, int64, error)
}

type vendorRepository struct {
	db *gorm.DB
}

func NewVendorRepository(db *gorm.DB) VendorRepository {
	return &vendorRepository{db: db}
}

func (r *vendorRepository) Create(vendor *models.Vendor) error {
	return r.db.Create(vendor).Error
}

func (r *vendorRepository) Update(vendor *models.Vendor) error {
	return r.db.Save(vendor).Error
}

func (r *vendorRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&models.Vendor{}, "vendor_id = ?", id).Error
}

func (r *vendorRepository) GetByID(id uuid.UUID) (*models.Vendor, error) {
	var vendor models.Vendor
	if err := r.db.First(&vendor, "vendor_id = ?", id).Error; err != nil {
		return nil, err
	}
	return &vendor, nil
}

func (r *vendorRepository) List(offset, limit int) ([]models.Vendor, int64, error) {
	var vendors []models.Vendor
	var total int64
	if err := r.db.Model(&models.Vendor{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := r.db.Offset(offset).Limit(limit).Find(&vendors).Error; err != nil {
		return nil, 0, err
	}
	return vendors, total, nil
}
