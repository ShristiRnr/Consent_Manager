package repository

import (
	"consultrnr/consent-manager/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type NotificationPreferencesRepo struct {
	db *gorm.DB
}

func NewNotificationPreferencesRepo(db *gorm.DB) *NotificationPreferencesRepo {
	return &NotificationPreferencesRepo{db: db}
}

func (r *NotificationPreferencesRepo) Get(userID uuid.UUID) (*models.NotificationPreferences, error) {
	var preferences models.NotificationPreferences
	if err := r.db.First(&preferences, "user_id = ?", userID).Error; err != nil {
		return nil, err
	}
	return &preferences, nil
}

func (r *NotificationPreferencesRepo) Update(preferences *models.NotificationPreferences) error {
	return r.db.Save(preferences).Error
}
