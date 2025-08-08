package repository

import (
	"time"

	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm/clause"
)

// EnsureUserTenantLink inserts or updates the user-tenant link to reflect consent tracking.
func EnsureUserTenantLink(userID, tenantID uuid.UUID) error {
	link := models.UserTenantLink{
		ID:             uuid.New(),
		UserID:         userID,
		TenantID:       tenantID,
		FirstGrantedAt: time.Now(),
		LastUpdatedAt:  time.Now(),
	}

	return db.MasterDB.
		Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "user_id"},
				{Name: "tenant_id"},
			},
			DoUpdates: clause.Assignments(map[string]any{
				"last_updated_at": time.Now(),
			}),
		}).
		Create(&link).Error
}

// GetUserTenantLinks returns all tenants a user has consent history with.
func GetUserTenantLinks(userID uuid.UUID) ([]models.UserTenantLink, error) {
	var links []models.UserTenantLink
	err := db.MasterDB.
		Where("user_id = ?", userID).
		Find(&links).Error
	return links, err
}
