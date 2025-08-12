package localization

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/models"
	"fmt"
	"log"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DataLocalizationService ensures data is stored and processed in compliance with Indian data localization requirements
type DataLocalizationService struct {
	cfg config.Config
}

// NewDataLocalizationService creates a new data localization service
func NewDataLocalizationService(cfg config.Config) *DataLocalizationService {
	return &DataLocalizationService{cfg: cfg}
}

// IsDataLocationCompliant checks if storing data for a tenant complies with Indian data localization requirements
func (dls *DataLocalizationService) IsDataLocationCompliant(tenantID uuid.UUID, db *gorm.DB) (bool, string) {
	// For Indian tenants or tenants requiring Indian data localization, ensure data is stored in India
	var tenant models.Tenant
	if err := db.Where("tenant_id = ?", tenantID).First(&tenant).Error; err != nil {
		log.Printf("Error fetching tenant: %v", err)
		return false, "Error fetching tenant information"
	}

	// Check if tenant requires Indian data localization (based on industry, location, etc.)
	if dls.requiresIndianLocalization(&tenant) {
		// Check if the database cluster is in India
		if !dls.isIndianCluster(tenant.Cluster) {
			return false, fmt.Sprintf("Tenant requires Indian data localization but data would be stored in %s cluster", tenant.Cluster)
		}
	}

	return true, "Data location is compliant with DPDP requirements"
}

// requiresIndianLocalization determines if a tenant requires Indian data localization
func (dls *DataLocalizationService) requiresIndianLocalization(tenant *models.Tenant) bool {
	// Tenants in India automatically require Indian data localization
	if tenant.Industry == "Indian" || tenant.CompanySize == "Indian" {
		return true
	}

	// Tenants in specific sectors may require Indian data localization
	indianSectors := []string{"Banking", "Financial Services", "Insurance", "Healthcare", "Telecom", "Government"}
	for _, sector := range indianSectors {
		if tenant.Industry == sector {
			return true
		}
	}

	return false
}

// isIndianCluster checks if a database cluster is located in India
func (dls *DataLocalizationService) isIndianCluster(cluster string) bool {
	// Define which clusters are located in India
	// In a real implementation, this would check actual cluster locations
	indianClusters := []string{"india-central", "india-south", "india-west", "mumbai", "bangalore", "chennai"}
	
	for _, indianCluster := range indianClusters {
		if cluster == indianCluster {
			return true
		}
	}
	
	// Default to false for non-Indian clusters
	return false
}

// GetCompliantClusterForTenant returns the appropriate cluster for a tenant based on data localization requirements
func (dls *DataLocalizationService) GetCompliantClusterForTenant(tenant *models.Tenant) string {
	// If tenant requires Indian data localization, return an Indian cluster
	if dls.requiresIndianLocalization(tenant) {
		// Return the default Indian cluster
		// In a real implementation, this might select from available Indian clusters
		return "india-central"
	}
	
	// For other tenants, return the default cluster
	return "default"
}

// ValidateDataTransfer checks if transferring data complies with DPDP requirements
func (dls *DataLocalizationService) ValidateDataTransfer(sourceTenantID, targetTenantID uuid.UUID, db *gorm.DB) (bool, string) {
	// Check if both tenants require Indian data localization
	var sourceTenant, targetTenant models.Tenant
	
	if err := db.Where("tenant_id = ?", sourceTenantID).First(&sourceTenant).Error; err != nil {
		return false, "Error fetching source tenant information"
	}
	
	if err := db.Where("tenant_id = ?", targetTenantID).First(&targetTenant).Error; err != nil {
		return false, "Error fetching target tenant information"
	}
	
	sourceRequiresIndia := dls.requiresIndianLocalization(&sourceTenant)
	targetRequiresIndia := dls.requiresIndianLocalization(&targetTenant)
	
	// If either tenant requires Indian data localization, ensure transfer complies
	if sourceRequiresIndia || targetRequiresIndia {
		// Check if transfer is within India
		if !dls.isIndianCluster(sourceTenant.Cluster) || !dls.isIndianCluster(targetTenant.Cluster) {
			return false, "Data transfer between tenants requires Indian data localization but one or both clusters are outside India"
		}
	}
	
	return true, "Data transfer is compliant with DPDP requirements"
}
