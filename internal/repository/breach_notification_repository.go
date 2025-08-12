package repository

import (
	"consultrnr/consent-manager/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type BreachNotificationRepository struct {
	db *gorm.DB
	encryptedRepo *EncryptedBreachNotificationRepository
}

func NewBreachNotificationRepository(db *gorm.DB) *BreachNotificationRepository {
	return &BreachNotificationRepository{db: db, encryptedRepo: NewEncryptedBreachNotificationRepository(db)}
}

func (r *BreachNotificationRepository) CreateBreachNotification(notification *models.BreachNotification) error {
	return r.encryptedRepo.CreateBreachNotification(notification)
}

func (r *BreachNotificationRepository) GetBreachNotificationByID(notificationID uuid.UUID) (*models.BreachNotification, error) {
	return r.encryptedRepo.GetBreachNotificationByID(notificationID)
}

func (r *BreachNotificationRepository) ListBreachNotifications(tenantID uuid.UUID) ([]models.BreachNotification, error) {
	return r.encryptedRepo.GetBreachNotificationsByTenant(tenantID)
}

func (r *BreachNotificationRepository) UpdateBreachNotification(notification *models.BreachNotification) error {
	return r.encryptedRepo.UpdateBreachNotification(notification)
}
