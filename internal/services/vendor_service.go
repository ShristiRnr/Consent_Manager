package services

import (
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"

	"github.com/google/uuid"
)

type VendorService interface {
	CreateVendor(vendor *models.Vendor) error
	UpdateVendor(id uuid.UUID, data models.Vendor) (*models.Vendor, error)
	DeleteVendor(id uuid.UUID) error
	GetVendorByID(id uuid.UUID) (*models.Vendor, error)
	ListVendors(page, limit int) ([]models.Vendor, int64, error)
}

type vendorService struct {
	repo repository.VendorRepository
}

func NewVendorService(repo repository.VendorRepository) VendorService {
	return &vendorService{repo: repo}
}

func (s *vendorService) CreateVendor(vendor *models.Vendor) error {
	return s.repo.Create(vendor)
}

func (s *vendorService) UpdateVendor(id uuid.UUID, data models.Vendor) (*models.Vendor, error) {
	vendor, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}
	vendor.Company = data.Company
	vendor.Email = data.Email
	vendor.Address = data.Address
	return vendor, s.repo.Update(vendor)
}

func (s *vendorService) DeleteVendor(id uuid.UUID) error {
	return s.repo.Delete(id)
}

func (s *vendorService) GetVendorByID(id uuid.UUID) (*models.Vendor, error) {
	return s.repo.GetByID(id)
}

func (s *vendorService) ListVendors(page, limit int) ([]models.Vendor, int64, error) {
	offset := (page - 1) * limit
	return s.repo.List(offset, limit)
}
