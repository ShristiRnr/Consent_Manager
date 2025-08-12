package services

import (
	"consultrnr/consent-manager/internal/repository"

	"github.com/google/uuid"
)

type DSRService struct {
	repo *repository.DSRRepository
}

func NewDSRService(repo *repository.DSRRepository) *DSRService {
	return &DSRService{repo: repo}
}

func (s *DSRService) ApproveDeleteRequest(requestID uuid.UUID) error {
	return s.repo.ApproveDeleteRequest(requestID)
}
