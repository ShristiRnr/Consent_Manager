// db/init_db.go
package db

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/models"
	"crypto/sha3"
	"encoding/hex"
	"log"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	MasterDB *gorm.DB
	Clusters map[string]*gorm.DB
)

func InitDB(cfg config.Config) {
	Clusters = make(map[string]*gorm.DB)

	if cfg.DatabaseURL == "" {
		log.Fatal("InitDB: DATABASE_URL is not set")
	}
	master, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{})
	if err != nil {
		log.Fatalf("InitDB: failed to connect to master DB: %v", err)
	}
	if err := master.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`).Error; err != nil {
		log.Fatalf("InitDB: failed to enable uuid-ossp on master DB: %v", err)
	}
	MasterDB = master
	log.Println("Connected & configured Master DB")

	clusterConfigs := map[string]string{
		"us-east": cfg.DatabaseUSEastURL,
		"eu-west": cfg.DatabaseEUWestURL,
	}
	for name, dsn := range clusterConfigs {
		if dsn == "" {
			log.Printf("InitDB: skipping cluster %s (no URL provided)", name)
			continue
		}

		dbConn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			log.Fatalf("InitDB: failed to connect to cluster %s DB: %v", name, err)
		}
		if err := dbConn.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`).Error; err != nil {
			log.Fatalf("InitDB: failed to enable uuid-ossp on cluster %s DB: %v", name, err)
		}
		Clusters[name] = dbConn
		log.Printf("Connected & configured cluster %s", name)
	}

	if err := MasterDB.AutoMigrate(
		&models.Tenant{},
		&models.AuditLog{},
		&models.MasterUser{},
		&models.DSRRequest{},
		&models.UserTenantLink{},
		&models.Notification{},
		&models.AdminLoginIndex{},
		&models.AdminUser{},
		// &models.WebhookConfig{},
		// &models.WebhookLog{},
		// &models.WebhookDelivery{},
		&models.APIKey{},
		// &models.WebhookQueue{},
	); err != nil {
		log.Fatalf("InitDB: public-schema migration failed on master: %v", err)
	}
	log.Println("Master DB migrations complete")
}

func GetTenantIDFromAPIKey(apiKey string) (uuid.UUID, error) {
	var link models.APIKey
	if err := MasterDB.
		Where("hashed_key = ? AND revoked = false", hex.EncodeToString(sha3.New256().Sum(nil))).
		First(&link).Error; err != nil {
		return uuid.Nil, err
	}
	return link.TenantID, nil
}
