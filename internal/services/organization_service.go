package services

import (
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"

	"github.com/google/uuid"
)

type OrganizationService struct {
	repo *repository.OrganizationRepository
}

func NewOrganizationService(repo *repository.OrganizationRepository) *OrganizationService {
	return &OrganizationService{repo: repo}
}

func (s *OrganizationService) CreateOrganization(organization *models.OrganizationEntity) error {
	return s.repo.Create(organization)
}

func (s *OrganizationService) UpdateOrganization(organization *models.OrganizationEntity) error {
	return s.repo.Update(organization)
}

func (s *OrganizationService) DeleteOrganization(id uuid.UUID) error {
	return s.repo.Delete(id)
}

func (s *OrganizationService) ListOrganizations() ([]models.OrganizationEntity, error) {
	return s.repo.List()
}

func (s *OrganizationService) GetOrganizationByID(id uuid.UUID) (*models.OrganizationEntity, error) {
	return s.repo.GetByID(id)
}

func (s *OrganizationService) GetOrganizationByName(name string) (*models.OrganizationEntity, error) {
	return s.repo.GetByName(name)
}

func (s *OrganizationService) GetOrganizationsByIndustry(industry string) ([]models.OrganizationEntity, error) {
	return s.repo.GetByIndustry(industry)
}
