// db/tenant_db.go
package db

import (
	"consultrnr/consent-manager/internal/models"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	gormschema "gorm.io/gorm/schema"
)

var (
	tenantClusterMap = map[string]string{} // tenant_id -> cluster
	tenantDBCache    sync.Map              // schema -> *gorm.DB
)

func RegisterTenantCluster(tenantID uuid.UUID, cluster string) error {
	tenantClusterMap[tenantID.String()] = cluster
	log.Info().Str("tenant_id", tenantID.String()).Str("cluster", cluster).Msg("Registering tenant cluster")
	return MasterDB.Model(&models.Tenant{}).
		Where("tenant_id = ?", tenantID).
		Update("cluster", cluster).Error
}

func GetTenantDB(schema string) (*gorm.DB, error) {
	log.Info().Str("schema", schema).Msg("Retrieving tenant DB")
	if db, ok := tenantDBCache.Load(schema); ok {
		log.Debug().Str("schema", schema).Msg("Tenant DB found in cache")
		return db.(*gorm.DB), nil
	}

	idPart := strings.TrimPrefix(schema, "tenant_")
	for tenantID, cluster := range tenantClusterMap {
		if strings.HasPrefix(tenantID, idPart) {
			log.Debug().Str("tenant_id", tenantID).Str("cluster", cluster).Msg("Tenant found in in-memory map")
			return loadTenantDB(schema, tenantID, cluster)
		}
	}

	var tenant models.Tenant
	if err := MasterDB.
		Where("tenant_id::text LIKE ?", idPart+"%").
		First(&tenant).Error; err != nil {
		log.Error().Err(err).Msg("Tenant not found in DB")
		return nil, errors.New("tenant not found in DB")
	}

	if tenant.Cluster == "" {
		log.Error().Str("tenant_id", tenant.TenantID.String()).Msg("Tenant cluster not set")
		return nil, errors.New("tenant cluster not set")
	}

	tenantClusterMap[tenant.TenantID.String()] = tenant.Cluster
	log.Info().Str("tenant_id", tenant.TenantID.String()).Str("cluster", tenant.Cluster).Msg("Tenant mapping loaded from MasterDB")
	return loadTenantDB(schema, tenant.TenantID.String(), tenant.Cluster)
}

func loadTenantDB(schema, tenantID, cluster string) (*gorm.DB, error) {
	log.Info().Str("tenant_id", tenantID).Str("cluster", cluster).Str("schema", schema).Msg("Loading tenant DB")
	clusterDB, ok := Clusters[cluster]
	if !ok {
		return nil, fmt.Errorf("cluster %s not found", cluster)
	}

	// New session for isolation
	tenantDB := clusterDB.Session(&gorm.Session{NewDB: true})

	// Make sure schema exists
	if err := tenantDB.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)).Error; err != nil {
		log.Error().Err(err).Msg("Failed to create schema")
		return nil, err
	}

	// Set table prefix for GORM (before AutoMigrate!)
	tenantDB.Config.NamingStrategy = gormschema.NamingStrategy{
		TablePrefix: schema + ".",
	}

	// Now migrate tables
	if err := tenantDB.AutoMigrate(
		&models.Consent{},
		&models.ConsentHistory{},
		&models.APIKey{},
		&models.Purpose{},
		&models.DataPrincipal{},
		&models.Grievance{},
		&models.Notification{},
		&models.AuditLog{},
		&models.DSRRequest{},
	); err != nil {
		log.Error().Err(err).Msg("AutoMigrate failed")
		return nil, err
	}

	tenantDBCache.Store(schema, tenantDB)
	log.Info().Str("schema", schema).Msg("Tenant DB loaded and cached")
	return tenantDB, nil
}

// Use your master DB to store API keys and tenants
func GetMasterDB() *gorm.DB {
	return MasterDB.Session(&gorm.Session{NewDB: true})
}

func HashAPIKey(rawKey string) string {
	sum := sha3.New256()
	sum.Write([]byte(rawKey))
	return hex.EncodeToString(sum.Sum(nil))
}

func LookupTenantByAPIKey(rawKey string) (*models.Tenant, error) {
	db := GetMasterDB()
	var apiKey models.APIKey
	hashedKey := HashAPIKey(rawKey)
	err := db.Where("hashed_key = ? AND revoked = false", hashedKey).First(&apiKey).Error
	if err != nil {
		return nil, errors.New("API key not found or revoked")
	}
	var tenant models.Tenant
	if err := db.Where("tenant_id = ?", apiKey.TenantID).First(&tenant).Error; err != nil {
		return nil, errors.New("Tenant not found for API key")
	}
	return &tenant, nil
}
