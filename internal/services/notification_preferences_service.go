package services

import (
	"context"

	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"
	"github.com/google/uuid"
)

type NotificationPreferencesService struct {
	repo *repository.NotificationPreferencesRepo
}

func NewNotificationPreferencesService(repo *repository.NotificationPreferencesRepo) *NotificationPreferencesService {
	return &NotificationPreferencesService{repo: repo}
}

func (s *NotificationPreferencesService) Get(ctx context.Context, userID uuid.UUID) (*models.NotificationPreferences, error) {
	return s.repo.Get(userID)
}

func (s *NotificationPreferencesService) Update(ctx context.Context, preferences *models.NotificationPreferences) error {
	return s.repo.Update(preferences)
}
