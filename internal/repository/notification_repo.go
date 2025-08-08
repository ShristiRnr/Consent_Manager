package repository

import (
	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type NotificationRepo struct {
	db *gorm.DB
}

func NewNotificationRepo(db *gorm.DB) *NotificationRepo {
	return &NotificationRepo{db: db}
}

// Create inserts a new notification record.
func (r *NotificationRepo) Create(n *models.Notification) error {
	return r.db.Create(n).Error
}

// List retrieves notifications for a user, with optional filtering by unread status and limit.
func (r *NotificationRepo) List(userID uuid.UUID, onlyUnread bool, limit int) ([]models.Notification, error) {
	query := r.db.Where("user_id = ?", userID)
	if onlyUnread {
		query = query.Where("unread = TRUE")
	}
	var notifications []models.Notification
	err := query.Order("created_at DESC").Limit(limit).Find(&notifications).Error
	return notifications, err
}

// MarkRead sets a specific notification's status to read.
func (r *NotificationRepo) MarkRead(userID, notifID uuid.UUID) error {
	return r.db.
		Model(&models.Notification{}).
		Where("id = ? AND user_id = ?", notifID, userID).
		Update("unread", false).Error
}

// MarkAllRead sets all unread notifications for a user as read.
func (r *NotificationRepo) MarkAllRead(userID uuid.UUID) error {
	return r.db.
		Model(&models.Notification{}).
		Where("user_id = ? AND unread = TRUE", userID).
		Update("unread", false).Error
}
