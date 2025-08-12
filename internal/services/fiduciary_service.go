package services

import (
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type FiduciaryService struct {
	repo *repository.FiduciaryRepository
}

type CreateFiduciaryRequest struct {
	Email    string    `json:"email" validate:"required,email"`
	Phone    string    `json:"phone" validate:"required"`
	Password string    `json:"password" validate:"required,min=8"`
	Name     string    `json:"name" validate:"required"`
	Role     string    `json:"role" validate:"required,oneof=admin editor viewer"`
	TenantID uuid.UUID `json:"tenantId" validate:"required"`
}

type UpdateFiduciaryRequest struct {
	Phone *string `json:"phone,omitempty"`
	Name  *string `json:"name,omitempty"`
	Role  *string `json:"role,omitempty"`
}

type FiduciaryResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Phone     string    `json:"phone"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	TenantID  uuid.UUID `json:"tenantId"`
	CreatedAt time.Time `json:"createdAt"`
}

func NewFiduciaryService(repo *repository.FiduciaryRepository) *FiduciaryService {
	return &FiduciaryService{repo: repo}
}

func (s *FiduciaryService) GetFiduciaryByID(userID uuid.UUID) (*FiduciaryResponse, error) {
	user, err := s.repo.GetFiduciaryByID(userID)
	if err != nil {
		return nil, err
	}
	return s.modelToResponse(user), nil
}

func (s *FiduciaryService) CreateFiduciary(req *CreateFiduciaryRequest) (*FiduciaryResponse, error) {
	if err := s.validateCreateFiduciaryRequest(req); err != nil {
		return nil, err
	}

	existingUser, _ := s.repo.GetFiduciaryByEmail(req.Email)
	if existingUser != nil {
		return nil, errors.New("fiduciary with this email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.FiduciaryUser{
		ID:           uuid.New(),
		Email:        strings.ToLower(strings.TrimSpace(req.Email)),
		Phone:        strings.TrimSpace(req.Phone),
		PasswordHash: string(hashedPassword),
		Name:         req.Name,
		Role:         req.Role,
		TenantID:     req.TenantID,
	}

	if err := s.repo.CreateFiduciary(user); err != nil {
		return nil, fmt.Errorf("failed to create fiduciary: %w", err)
	}

	return s.modelToResponse(user), nil
}

func (s *FiduciaryService) UpdateFiduciary(userID uuid.UUID, req *UpdateFiduciaryRequest) (*FiduciaryResponse, error) {
	user, err := s.repo.GetFiduciaryByID(userID)
	if err != nil {
		return nil, fmt.Errorf("fiduciary not found: %w", err)
	}

	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Phone != nil {
		user.Phone = *req.Phone
	}
	if req.Role != nil {
		if err := s.validateRole(*req.Role); err != nil {
			return nil, err
		}
		user.Role = *req.Role
	}

	if err := s.repo.UpdateFiduciary(user); err != nil {
		return nil, fmt.Errorf("failed to update fiduciary: %w", err)
	}

	return s.modelToResponse(user), nil
}

func (s *FiduciaryService) DeleteFiduciary(userID uuid.UUID) error {
	_, err := s.repo.GetFiduciaryByID(userID)
	if err != nil {
		return fmt.Errorf("fiduciary not found: %w", err)
	}

	if err := s.repo.DeleteFiduciary(userID); err != nil {
		return fmt.Errorf("failed to delete fiduciary: %w", err)
	}

	return nil
}

func (s *FiduciaryService) ListFiduciaries(params repository.FiduciaryListParams) (*repository.FiduciaryListResponse, error) {
	if params.Page <= 0 {
		params.Page = 1
	}
	if params.Limit <= 0 {
		params.Limit = 20
	}
	if params.Limit > 100 {
		params.Limit = 100 // Max limit
	}

	return s.repo.ListFiduciaries(params)
}

func (s *FiduciaryService) validateCreateFiduciaryRequest(req *CreateFiduciaryRequest) error {
	if req.Email == "" {
		return errors.New("email is required")
	}
	if !s.isValidEmail(req.Email) {
		return errors.New("invalid email format")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	if len(req.Password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	if req.Name == "" {
		return errors.New("name is required")
	}
	if err := s.validateRole(req.Role); err != nil {
		return err
	}
	return nil
}

func (s *FiduciaryService) validateRole(role string) error {
	validRoles := []string{"admin", "editor", "viewer"}
	for _, validRole := range validRoles {
		if role == validRole {
			return nil
		}
	}
	return fmt.Errorf("invalid role: %s. Valid roles are: %s", role, strings.Join(validRoles, ", "))
}

func (s *FiduciaryService) isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func (s *FiduciaryService) modelToResponse(user *models.FiduciaryUser) *FiduciaryResponse {
	return &FiduciaryResponse{
		ID:        user.ID,
		Email:     user.Email,
		Phone:     user.Phone,
		Name:      user.Name,
		Role:      user.Role,
		TenantID:  user.TenantID,
		CreatedAt: user.CreatedAt,
	}
}
