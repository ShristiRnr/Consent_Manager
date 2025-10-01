package main

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"fmt"
	"log"
)

func main() {
	cfg := config.LoadConfig()
	db.InitDB(cfg)

	result := db.MasterDB.Model(&models.Tenant{}).
		Where("review_frequency_months IS NULL OR review_frequency_months <= 0").
		Update("review_frequency_months", 6)

	if result.Error != nil {
		log.Fatalf("❌ Failed to update tenants: %v", result.Error)
	}

	err := db.MasterDB.AutoMigrate(&models.ConsentForm{},
		&models.ConsentFormPurpose{},
		&models.FiduciaryUser{},
		&models.OrganizationEntity{},
		&models.DataPrincipal{},
	)
	if err != nil {
		log.Fatalf("❌ Failed to migrate database: %v", err)
	}

	fmt.Println("✅ Database migration successful")

	fmt.Printf("✅ Updated %d tenants to default review frequency of 6 months\n", result.RowsAffected)
}
