package repository

import (
	"consultrnr/consent-manager/internal/models"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type FiduciaryRepository struct {
	db *gorm.DB
}

type FiduciaryListParams struct {
	Page     int
	Limit    int
	Search   string
	Role     string
	SortBy   string
	SortDesc bool
	TenantID *uuid.UUID
}

type FiduciaryListResponse struct {
	Users      []models.FiduciaryUser `json:"users"`
	Total      int64                  `json:"total"`
	Page       int                    `json:"page"`
	Limit      int                    `json:"limit"`
	TotalPages int                    `json:"totalPages"`
}

func NewFiduciaryRepository(db *gorm.DB) *FiduciaryRepository {
	return &FiduciaryRepository{db: db}
}

func (r *FiduciaryRepository) GetFiduciaryByID(userID uuid.UUID) (*models.FiduciaryUser, error) {
	var user models.FiduciaryUser
	if err := r.db.First(&user, "id = ?", userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *FiduciaryRepository) GetFiduciaryByEmail(email string) (*models.FiduciaryUser, error) {
	var user models.FiduciaryUser
	if err := r.db.First(&user, "email = ?", email).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *FiduciaryRepository) CreateFiduciary(user *models.FiduciaryUser) error {
	return r.db.Create(user).Error
}

func (r *FiduciaryRepository) UpdateFiduciary(user *models.FiduciaryUser) error {
	return r.db.Save(user).Error
}

func (r *FiduciaryRepository) DeleteFiduciary(userID uuid.UUID) error {
	return r.db.Delete(&models.FiduciaryUser{}, "id = ?", userID).Error
}

func (r *FiduciaryRepository) ListFiduciaries(params FiduciaryListParams) (*FiduciaryListResponse, error) {
	var users []models.FiduciaryUser
	var total int64

	query := r.db.Model(&models.FiduciaryUser{})

	if params.TenantID != nil {
		query = query.Where("tenant_id = ?", *params.TenantID)
	}

	if params.Search != "" {
		searchTerm := "%" + strings.ToLower(params.Search) + "%"
		query = query.Where(
			"LOWER(name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(phone) LIKE ?",
			searchTerm, searchTerm, searchTerm,
		)
	}

	if params.Role != "" {
		query = query.Where("role = ?", params.Role)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	sortBy := "created_at"
	if params.SortBy != "" {
		sortBy = params.SortBy
	}
	sortOrder := "ASC"
	if params.SortDesc {
		sortOrder = "DESC"
	}
	query = query.Order(fmt.Sprintf("%s %s", sortBy, sortOrder))

	if params.Limit > 0 {
		offset := (params.Page - 1) * params.Limit
		query = query.Offset(offset).Limit(params.Limit)
	}

	if err := query.Find(&users).Error; err != nil {
		return nil, err
	}

	totalPages := 0
	if params.Limit > 0 {
		totalPages = int((total + int64(params.Limit) - 1) / int64(params.Limit))
	}

	return &FiduciaryListResponse{
		Users:      users,
		Total:      total,
		Page:       params.Page,
		Limit:      params.Limit,
		TotalPages: totalPages,
	}, nil
}

func (r *FiduciaryRepository) GetFiduciariesByRole(role string) ([]models.FiduciaryUser, error) {
	var users []models.FiduciaryUser
	if err := r.db.Where("role = ?", role).Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (r *FiduciaryRepository) BulkUpdateFiduciaries(userIDs []uuid.UUID, updates map[string]interface{}) error {
	return r.db.Model(&models.FiduciaryUser{}).Where("id IN ?", userIDs).Updates(updates).Error
}

func (r *FiduciaryRepository) BulkDeleteFiduciaries(userIDs []uuid.UUID) error {
	return r.db.Where("id IN ?", userIDs).Delete(&models.FiduciaryUser{}).Error
}