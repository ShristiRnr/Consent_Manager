package repository

import (
	"consultrnr/consent-manager/internal/models"
	"gorm.io/gorm"
)

type AuditRepo struct {
	db *gorm.DB
}

func NewAuditRepo(db *gorm.DB) *AuditRepo {
	return &AuditRepo{db: db}
}

func (r *AuditRepo) Create(logEntry *models.AuditLog) error {
	return r.db.Create(logEntry).Error
}

func (r *AuditRepo) GetByTenant(tenantID string) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := r.db.Where("tenant_id = ?", tenantID).Order("timestamp desc").Find(&logs).Error
	return logs, err
}
