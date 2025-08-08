// internal/services/grievance_service.go

package services

import (
	"context"
	"time"

	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"

	"github.com/google/uuid"
)

type GrievanceService struct {
	repo *repository.GrievanceRepository
}

func NewGrievanceService(repo *repository.GrievanceRepository) *GrievanceService {
	return &GrievanceService{repo: repo}
}

// Raise a new grievance
func (s *GrievanceService) Raise(ctx context.Context, req dto.CreateGrievanceRequest, tenantID string) (*models.Grievance, error) {
	g := &models.Grievance{
		ID:                   uuid.New(),
		UserID:               uuid.MustParse(req.UserID),
		TenantID:             uuid.MustParse(tenantID),
		GrievanceType:        req.GrievanceType,
		GrievanceSubject:     req.GrievanceSubject,
		GrievanceDescription: req.GrievanceDescription,
		Status:               "open",
		AssignedTo:           nil,
		Category:             req.Category,
		Priority:             req.Priority,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := s.repo.Create(ctx, g); err != nil {
		return nil, err
	}
	return g, nil
}

// Get a grievance by ID
func (s *GrievanceService) GetByID(ctx context.Context, grievanceID string) (*models.Grievance, error) {
	return s.repo.GetByID(ctx, grievanceID)
}

// List grievances for a tenant (optional status filter)
func (s *GrievanceService) List(ctx context.Context, tenantID string, status *string) ([]models.Grievance, error) {
	return s.repo.List(ctx, tenantID, status)
}

// List grievances for a specific user
func (s *GrievanceService) ListForUser(ctx context.Context, userID string) ([]models.Grievance, error) {
	return s.repo.ListForUser(ctx, userID)
}

// Update grievance status or assign admin
func (s *GrievanceService) Resolve(ctx context.Context, id string, req dto.UpdateGrievanceRequest) error {
	var assignedTo *string
	if req.AssignedTo != "" {
		assignedTo = &req.AssignedTo
	}
	return s.repo.UpdateStatus(ctx, id, req.Status, assignedTo)
}

// Update grievance details
func (s *GrievanceService) UpdateDetails(ctx context.Context, id string, req dto.UpdateGrievanceDetailsRequest) error {
	updates := map[string]interface{}{}
	if req.GrievanceSubject != "" {
		updates["grievance_subject"] = req.GrievanceSubject
	}
	if req.GrievanceDescription != "" {
		updates["grievance_description"] = req.GrievanceDescription
	}
	if req.GrievanceType != "" {
		updates["grievance_type"] = req.GrievanceType
	}
	if req.Category != "" {
		updates["category"] = req.Category
	}
	if req.Priority != "" {
		updates["priority"] = req.Priority
	}
	return s.repo.UpdateDetails(ctx, id, updates)
}

// Delete a grievance
func (s *GrievanceService) Delete(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

// ===================== Chat/Comments =====================

// Add a comment to a grievance (user or admin)
func (s *GrievanceService) AddComment(ctx context.Context, req dto.CreateGrievanceCommentRequest) (*models.GrievanceComment, error) {
	comment := &models.GrievanceComment{
		ID:          uuid.New(),
		GrievanceID: uuid.MustParse(req.GrievanceID),
		UserID:      uuid.MustParse(req.UserID),
		Comment:     req.Comment,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Optional admin ID
	if req.AdminID != "" {
		adminUUID := uuid.MustParse(req.AdminID)
		comment.AdminId = &adminUUID
	}

	if err := s.repo.CreateComment(ctx, comment); err != nil {
		return nil, err
	}
	return comment, nil
}

// List all comments for a grievance (chat history)
func (s *GrievanceService) GetComments(ctx context.Context, grievanceID string) ([]models.GrievanceComment, error) {
	return s.repo.ListComments(ctx, grievanceID)
}

// Delete a specific comment
func (s *GrievanceService) DeleteComment(ctx context.Context, commentID string) error {
	return s.repo.DeleteComment(ctx, commentID)
}
