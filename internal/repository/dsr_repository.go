package repository

import (
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type DSRRepository struct {
	MasterDB *gorm.DB
	TenantDB *gorm.DB
}

func NewDSRRepository(masterDB, tenantDB *gorm.DB) *DSRRepository {
	return &DSRRepository{MasterDB: masterDB, TenantDB: tenantDB}
}

func (r *DSRRepository) ApproveDeleteRequest(requestID uuid.UUID) error {
	tx := r.MasterDB.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	// 1. Fetch the DSR request
	var dsr models.DSRRequest
	if err := tx.First(&dsr, "id = ?", requestID).Error; err != nil {
		tx.Rollback()
		return err
	}

	// 2. Connect to the tenant-specific database
	tenantDB, err := db.GetTenantDB(dsr.TenantID.String())
	if err != nil {
		tx.Rollback()
		return err
	}

	// 3. Delete all user data from the tenant schema in a transaction
	tenantTx := tenantDB.Begin()
	if tenantTx.Error != nil {
		tx.Rollback()
		return tenantTx.Error
	}

	userID := dsr.UserID
	// Delete associated data first to avoid foreign key violations
	tenantTx.Where("data_principal_id = ?", userID).Delete(&models.Consent{})
	tenantTx.Where("data_principal_id = ?", userID).Delete(&models.Grievance{})
	tenantTx.Where("user_id = ?", userID).Delete(&models.AuditLog{}) // Assuming AuditLog might be different, check schema
	tenantTx.Where("data_principal_id = ?", userID).Delete(&models.Notification{})
	// Now delete the user record from the tenant
	tenantTx.Where("id = ?", userID).Delete(&models.DataPrincipal{})

	if err := tenantTx.Commit().Error; err != nil {
		tenantTx.Rollback()
		tx.Rollback()
		return err
	}

	// 5. Mark the DSR request as "Completed"
	dsr.Status = "Completed"
	dsr.ResolutionNote = "User data permanently deleted."
	dsr.ResolvedAt = gorm.DeletedAt{Time: time.Now(), Valid: true}
	if err := tx.Save(&dsr).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}
