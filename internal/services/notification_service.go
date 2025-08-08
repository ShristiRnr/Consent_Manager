package services

import (
	"context"
	"fmt"

	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/realtime"
	"consultrnr/consent-manager/internal/repository"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type NotificationService struct {
	repo *repository.NotificationRepo
	hub  *realtime.Hub
}

func NewNotificationService(repo *repository.NotificationRepo, hub *realtime.Hub) *NotificationService {
	return &NotificationService{repo: repo, hub: hub}
}

func (s *NotificationService) Create(ctx context.Context, n *models.Notification) error {
	if err := s.repo.Create(n); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("user_id", n.UserID.String()).Msg("Failed to create notification")
		return fmt.Errorf("create notification: %w", err)
	}
	s.hub.Publish(n.UserID, n)
	return nil
}

func (s *NotificationService) List(ctx context.Context, user uuid.UUID, unread bool, limit int) ([]models.Notification, error) {
	list, err := s.repo.List(user, unread, limit)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("user_id", user.String()).Msg("Failed to list notifications")
		return nil, fmt.Errorf("list notifications: %w", err)
	}
	return list, nil
}

func (s *NotificationService) MarkRead(ctx context.Context, user, id uuid.UUID) error {
	if err := s.repo.MarkRead(user, id); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("user_id", user.String()).Str("notif_id", id.String()).Msg("Failed to mark notification as read")
		return fmt.Errorf("mark notification read: %w", err)
	}
	s.hub.Publish(user, map[string]any{"read": id})
	return nil
}

func (s *NotificationService) MarkAllRead(ctx context.Context, user uuid.UUID) error {
	if err := s.repo.MarkAllRead(user); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("user_id", user.String()).Msg("Failed to mark all notifications as read")
		return fmt.Errorf("mark all notifications read: %w", err)
	}
	s.hub.Publish(user, map[string]any{"read_all": true})
	return nil
}
