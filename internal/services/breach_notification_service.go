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

func (s *BreachNotificationService) GetByID(notificationID uuid.UUID) (*models.BreachNotification, error) {
	return s.repo.GetBreachNotificationByID(notificationID)
}

func (s *BreachNotificationService) Update(notification *models.BreachNotification) error {
	return s.repo.UpdateBreachNotification(notification)
}

func (s *BreachNotificationService) Delete(notificationID uuid.UUID) error {
	return s.repo.DeleteBreachNotification(notificationID)
}

func (s *BreachNotificationService) GetStatsByTenant(tenantID uuid.UUID) (map[string]interface{}, error) {
	notifications, err := s.repo.ListBreachNotifications(tenantID)
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total":     len(notifications),
		"pending":   0,
		"resolved":  0,
		"critical":  0,
		"high":      0,
		"medium":    0,
		"low":       0,
		"timestamp": "2025-09-26T22:35:00Z",
	}

	for _, notification := range notifications {
		switch notification.Status {
		case "pending":
			stats["pending"] = stats["pending"].(int) + 1
		case "resolved":
			stats["resolved"] = stats["resolved"].(int) + 1
		}

		switch notification.Severity {
		case "critical":
			stats["critical"] = stats["critical"].(int) + 1
		case "high":
			stats["high"] = stats["high"].(int) + 1
		case "medium":
			stats["medium"] = stats["medium"].(int) + 1
		case "low":
			stats["low"] = stats["low"].(int) + 1
		}
	}

	return stats, nil
}
