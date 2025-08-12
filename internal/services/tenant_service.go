package services

import (
	"context"
	"fmt"

	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

func CreateTenant(ctx context.Context, db *gorm.DB, name, domain string) (*models.Tenant, error) {
	tenantID := uuid.New()
	tenant := &models.Tenant{
		TenantID: tenantID,
		Name:     name,
		Domain:   domain,
	}

	if err := db.WithContext(ctx).Create(&tenant).Error; err != nil {
		log.Ctx(ctx).Error().Err(err).Str("domain", domain).Msg("Failed to create tenant entry")
		return nil, fmt.Errorf("create tenant: %w", err)
	}

	schema := fmt.Sprintf("tenant_%s", tenantID.String()[:8])
	if err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)).Error; err != nil {
		log.Ctx(ctx).Error().Err(err).Str("schema", schema).Msg("Failed to create schema")
		return nil, fmt.Errorf("create schema: %w", err)
	}

	gdb, err := db.Session(&gorm.Session{}).WithContext(ctx).DB()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("Failed to get DB connection for tenant schema")
		return nil, fmt.Errorf("get db connection: %w", err)
	}

	tenantDB, err := gorm.Open(db.Dialector, &gorm.Config{ConnPool: gdb})
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("Failed to open gorm DB for tenant")
		return nil, fmt.Errorf("gorm open for tenant: %w", err)
	}

	tenantDB = tenantDB.Exec(fmt.Sprintf("SET search_path TO %s", schema))
	if err := tenantDB.AutoMigrate(
		&models.DataPrincipal{},
		&models.FiduciaryUser{},
		&models.Purpose{},
		&models.Consent{},
		&models.ConsentHistory{},
		&models.DSRRequest{},
		&models.AuditLog{},
		&models.Grievance{},
		&models.Notification{},
	); err != nil {
		log.Ctx(ctx).Error().Err(err).Str("schema", schema).Msg("Failed to auto-migrate tenant schema")
		return nil, fmt.Errorf("auto migrate tenant schema: %w", err)
	}

	log.Ctx(ctx).Info().Str("tenant", name).Str("schema", schema).Msg("Tenant schema created and migrated")
	return tenant, nil
}
