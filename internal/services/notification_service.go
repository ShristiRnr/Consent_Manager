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
	repo                        *repository.NotificationRepo
	notificationPreferencesRepo *repository.NotificationPreferencesRepo
	emailService                *EmailService
	hub                         *realtime.Hub
	fiduciaryService            *FiduciaryService
}

func NewNotificationService(repo *repository.NotificationRepo, notificationPreferencesRepo *repository.NotificationPreferencesRepo, emailService *EmailService, hub *realtime.Hub, fiduciaryService *FiduciaryService) *NotificationService {
	return &NotificationService{repo: repo, notificationPreferencesRepo: notificationPreferencesRepo, emailService: emailService, hub: hub, fiduciaryService: fiduciaryService}
}

func (s *NotificationService) Create(ctx context.Context, n *models.Notification) error {
	if err := s.repo.Create(n); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("user_id", n.UserID.String()).Msg("Failed to create notification")
		return fmt.Errorf("create notification: %w", err)
	}
	s.hub.Publish(n.UserID, n)

	// Send email notification
	preferences, err := s.notificationPreferencesRepo.Get(n.UserID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("user_id", n.UserID.String()).Msg("Failed to get notification preferences")
		// Don't block notification creation if preferences are not found
		return nil
	}

	fiduciary, err := s.fiduciaryService.GetFiduciaryByID(n.UserID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("user_id", n.UserID.String()).Msg("Failed to get fiduciary for email notification")
		return nil
	}
	userEmail := fiduciary.Email

	switch n.Title {
	case "New Grievance":
		if preferences.OnNewGrievance {
			s.emailService.Send(userEmail, n.Title, n.Body)
		}
	case "Grievance Update":
		if preferences.OnGrievanceUpdate {
			s.emailService.Send(userEmail, n.Title, n.Body)
		}
	case "Consent Update":
		if preferences.OnConsentUpdate {
			s.emailService.Send(userEmail, n.Title, n.Body)
		}
	case "New Consent Request":
		if preferences.OnNewConsentRequest {
			s.emailService.Send(userEmail, n.Title, n.Body)
		}
	case "Data Subject Request":
		if preferences.OnDataSubjectRequest {
			s.emailService.Send(userEmail, n.Title, n.Body)
		}
	case "Data Subject Request Update":
		if preferences.OnDataSubjectRequestUpdate {
			s.emailService.Send(userEmail, n.Title, n.Body)
		}
	}

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
