package main

import (
	"fmt"
	"os"

	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/log"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func main() {
	log.InitLogger()
	cfg := config.LoadConfig()
	db.InitDB(cfg)

	tenantName := os.Getenv("TENANT_NAME")
	cluster := os.Getenv("TENANT_CLUSTER")

	if tenantName == "" || cluster == "" {
		log.Logger.Fatal().Msg("TENANT_NAME and TENANT_CLUSTER must be set")
	}

	tenantID := uuid.New()
	schema := "tenant_" + tenantID.String()[:8]
	clusterDB := db.Clusters[cluster]

	tenant := &models.Tenant{
		TenantID:              tenantID,
		Name:                  tenantName,
		Cluster:               cluster,
		ReviewFrequencyMonths: 6,
	}

	if err := db.MasterDB.Create(&tenant).Error; err != nil {
		log.Logger.Fatal().Err(err).Msg("Failed to insert tenant")
	}

	db.RegisterTenantCluster(tenantID, cluster)

	if err := clusterDB.Exec("CREATE SCHEMA IF NOT EXISTS " + schema).Error; err != nil {
		log.Logger.Fatal().Err(err).Msg("Failed to create schema")
	}

	gormTenant, err := clusterDB.Session(&gorm.Session{}).Set("gorm:table_options", fmt.Sprintf("SET search_path TO %s", schema)).DB()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("Failed to get tenant DB session")
	}

	gdb, err := gorm.Open(clusterDB.Dialector, &gorm.Config{
		ConnPool: gormTenant,
	})
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("Failed to open tenant scoped DB")
	}

	err = gdb.AutoMigrate(
		&models.DataPrincipal{},
		&models.Consent{},
		&models.ConsentHistory{},
		&models.Purpose{},
		&models.DSRRequest{},
		&models.AuditLog{},
		&models.Grievance{},
		&models.Notification{},
		&models.APIKey{},
	)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("Migration failed for tenant schema")
	}

	log.Logger.Info().
		Str("tenant_name", tenantName).
		Str("tenant_id", tenantID.String()).
		Str("cluster", cluster).
		Str("schema", schema).
		Msg("Tenant setup complete")
}
