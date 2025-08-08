package repository

import (
	"context"
	"log"
	"time"

	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type GrievanceRepository struct {
	db *gorm.DB
}

func NewGrievanceRepo(db *gorm.DB) *GrievanceRepository {
	return &GrievanceRepository{db: db}
}

// ===================== Grievance CRUD =====================

// Create a new grievance
func (r *GrievanceRepository) Create(ctx context.Context, g *models.Grievance) error {
	if err := r.db.WithContext(ctx).Create(g).Error; err != nil {
		log.Printf("Error creating grievance: %v", err)
		return err
	}

	// Add audit log in tenant DB
	tenantSchema := "tenant_" + g.TenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		log.Printf("Error getting tenant DB for tenant %s: %v", g.TenantID, err)
		return err
	}

	auditLog := models.AuditLog{
		LogID:        uuid.New(),
		UserID:       g.UserID,
		TenantID:     g.TenantID,
		ActionType:   "Created Grievance",
		Initiator:    "User",
		Timestamp:    time.Now(),
		Jurisdiction: "India",
	}
	if err := tenantDB.Create(&auditLog).Error; err != nil {
		log.Printf("Error creating audit log: %v", err)
		return err
	}

	return nil
}

// Get a grievance by ID
func (r *GrievanceRepository) GetByID(ctx context.Context, grievanceID string) (*models.Grievance, error) {
	var grievance models.Grievance
	if err := r.db.WithContext(ctx).
		Where("id = ?", grievanceID).
		First(&grievance).Error; err != nil {
		return nil, err
	}
	return &grievance, nil
}

// List grievances for a tenant, optionally filter by status
func (r *GrievanceRepository) List(ctx context.Context, tenantID string, status *string) ([]models.Grievance, error) {
	query := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID)
	if status != nil {
		query = query.Where("status = ?", *status)
	}
	var grievances []models.Grievance
	err := query.Order("created_at DESC").Find(&grievances).Error
	if err != nil && err == gorm.ErrRecordNotFound {
		return nil, gorm.ErrRecordNotFound
	}
	if err != nil {
		log.Printf("Error listing grievances: %v", err)
		return nil, err
	}
	return grievances, nil
}

// List grievances for a specific user
func (r *GrievanceRepository) ListForUser(ctx context.Context, userID string) ([]models.Grievance, error) {
	var grievances []models.Grievance
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&grievances).Error
	return grievances, err
}

// Update grievance status or assign admin
func (r *GrievanceRepository) UpdateStatus(ctx context.Context, id, status string, assignedTo *string) error {
	updates := map[string]interface{}{
		"status":     status,
		"updated_at": gorm.Expr("NOW()"),
	}
	if assignedTo != nil {
		updates["assigned_to"] = *assignedTo
	}
	if err := r.db.WithContext(ctx).
		Model(&models.Grievance{}).
		Where("id = ?", id).
		Updates(updates).Error; err != nil {
		log.Printf("Error updating grievance status: %v", err)
		return err
	}
	return nil
}

// Update grievance details (e.g., subject, description)
func (r *GrievanceRepository) UpdateDetails(ctx context.Context, id string, updates map[string]interface{}) error {
	updates["updated_at"] = gorm.Expr("NOW()")
	if err := r.db.WithContext(ctx).
		Model(&models.Grievance{}).
		Where("id = ?", id).
		Updates(updates).Error; err != nil {
		log.Printf("Error updating grievance details: %v", err)
		return err
	}
	return nil
}

// Delete grievance
func (r *GrievanceRepository) Delete(ctx context.Context, id string) error {
	if err := r.db.WithContext(ctx).
		Where("id = ?", id).
		Delete(&models.Grievance{}).Error; err != nil {
		log.Printf("Error deleting grievance: %v", err)
		return err
	}
	return nil
}

// ===================== Grievance Comment (Chat) =====================

// Create a new comment (user or admin)
func (r *GrievanceRepository) CreateComment(ctx context.Context, comment *models.GrievanceComment) error {
	if err := r.db.WithContext(ctx).Create(comment).Error; err != nil {
		log.Printf("Error creating grievance comment: %v", err)
		return err
	}
	return nil
}

// List comments for a grievance (chat history)
func (r *GrievanceRepository) ListComments(ctx context.Context, grievanceID string) ([]models.GrievanceComment, error) {
	var comments []models.GrievanceComment
	err := r.db.WithContext(ctx).
		Where("grievance_id = ?", grievanceID).
		Order("created_at ASC"). // ASC for chat order
		Find(&comments).Error
	if err != nil {
		log.Printf("Error listing grievance comments: %v", err)
		return nil, err
	}
	return comments, nil
}

// Delete a specific comment
func (r *GrievanceRepository) DeleteComment(ctx context.Context, commentID string) error {
	if err := r.db.WithContext(ctx).
		Where("id = ?", commentID).
		Delete(&models.GrievanceComment{}).Error; err != nil {
		log.Printf("Error deleting grievance comment: %v", err)
		return err
	}
	return nil
}
