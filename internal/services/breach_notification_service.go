package services

import (
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"
	"github.com/google/uuid"
)

type BreachNotificationService struct {
	repo *repository.BreachNotificationRepository
}

func NewBreachNotificationService(repo *repository.BreachNotificationRepository) *BreachNotificationService {
	return &BreachNotificationService{repo: repo}
}

func (s *BreachNotificationService) CreateBreachNotification(notification *models.BreachNotification) error {
	notification.ID = uuid.New()
	return s.repo.CreateBreachNotification(notification)
}

func (s *BreachNotificationService) GetBreachNotificationByID(notificationID uuid.UUID) (*models.BreachNotification, error) {
	return s.repo.GetBreachNotificationByID(notificationID)
}

func (s *BreachNotificationService) ListBreachNotifications(tenantID uuid.UUID) ([]models.BreachNotification, error) {
	return s.repo.ListBreachNotifications(tenantID)
}

func (s *BreachNotificationService) UpdateBreachNotification(notification *models.BreachNotification) error {
	return s.repo.UpdateBreachNotification(notification)
}
