package repository

import (
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/encryption"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type EncryptedConsentRepository struct {
	db *gorm.DB
}

func NewEncryptedConsentRepository(db *gorm.DB) *EncryptedConsentRepository {
	return &EncryptedConsentRepository{db: db}
}

func (r *EncryptedConsentRepository) DB() *gorm.DB {
	return r.db
}

func (r *EncryptedConsentRepository) GetUserConsents(masterDB *gorm.DB, tenantDBs map[uuid.UUID]*gorm.DB, userID uuid.UUID) ([]models.Consent, error) {
	var links []models.UserTenantLink
	log.Println("fettching user consents for user ID:", userID)
	// Find all tenant links for this user from the Master DB
	if err := masterDB.Where("user_id = ?", userID).Find(&links).Error; err != nil {
		log.Printf("Error fetching user tenant links for user %s: %v", userID, err)
		return nil, err
	}

	var allConsents []models.Consent
	for _, link := range links {
		tenantSchema := "tenant_" + link.TenantID.String()[:8]
		tenantDB, _ := db.GetTenantDB(tenantSchema)
		log.Printf("Processing tenant link for user %s in tenant %s", userID, link.TenantID)
		if tenantDB == nil {
			log.Printf("No tenant DB found for tenant ID %s", link.TenantID)
			continue // Skip if no tenant DB is available
		}
		consent, err := r.GetUserConsentInTenant(tenantDB, link.TenantID, userID)
		log.Printf("Fetching consent for user %s in tenant %s", userID, link.TenantID)
		if err != nil {
			return nil, err
		}
		if consent != nil {
			log.Printf("Consents found for user %s in tenant %s: %+v", userID, link.TenantID, consent)
			allConsents = append(allConsents, *consent)
		}
	}

	return allConsents, nil
}

// GetConsentByID retrieves a consent record by its ID and tenant ID.
func (r *EncryptedConsentRepository) GetConsentByID(ctx context.Context, consentID uuid.UUID, tenantID uuid.UUID) (*models.Consent, error) {
	//get tenant DB based on tenant ID
	tenantSchema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		log.Printf("Error getting tenant DB for tenant %s: %v", tenantID, err)
		return nil, err
	}
	var encryptedConsent models.EncryptedConsent
	if err := tenantDB.Where("id = ? AND tenant_id = ?", consentID, tenantID).First(&encryptedConsent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRecordNotFound // Consent not found
		}
		return nil, err // Other error
	}
	return r.decryptConsent(&encryptedConsent) // Successfully found consent
}

// Get all consents in a tenant (admin)
func (r *EncryptedConsentRepository) GetAllConsentsByTenant(tenantDB *gorm.DB, tenantID uuid.UUID) ([]models.Consent, error) {
	var encryptedConsents []models.EncryptedConsent
	err := tenantDB.Where("tenant_id = ?", tenantID).Find(&encryptedConsents).Error
	if err != nil {
		return nil, err
	}
	
	var consents []models.Consent
	for _, encryptedConsent := range encryptedConsents {
		consent, err := r.decryptConsent(&encryptedConsent)
		if err != nil {
			return nil, err
		}
		consents = append(consents, *consent)
	}
	return consents, err
}

// Get consent for a user in a tenant (admin)
func (r *EncryptedConsentRepository) GetUserConsentInTenant(tenantDB *gorm.DB, tenantID, userID uuid.UUID) (*models.Consent, error) {
	var encryptedConsent models.EncryptedConsent
	err := tenantDB.Where("tenant_id = ? AND user_id = ?", tenantID, userID).First(&encryptedConsent).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r.decryptConsent(&encryptedConsent)
}

func (r *EncryptedConsentRepository) GetPurposesByTenant(tenantID uuid.UUID) (dto.ConsentPurposes, error) {
	var encryptedConsent models.EncryptedConsent
	if err := r.db.Where("tenant_id = ?", tenantID).First(&encryptedConsent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.ConsentPurposes{}, nil // No consent found for this tenant
		}
		log.Printf("Error fetching consent for tenant %s: %v", tenantID, err)
		return dto.ConsentPurposes{}, err
	}
	// Extract and return the actual slice of Purpose items
	var purposes dto.ConsentPurposes
	if err := purposes.Scan(encryptedConsent.Purposes); err != nil {
		return dto.ConsentPurposes{}, err
	}
	return purposes, nil
}

func (r *EncryptedConsentRepository) UpsertConsent(consent *models.Consent) error {
	encryptedConsent, err := r.encryptConsent(consent)
	if err != nil {
		return err
	}
	
	var existing models.EncryptedConsent
	err = r.db.Where("uid = ?", consent.ID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.Create(encryptedConsent).Error
	} else if err != nil {
		return err
	}
	
	return r.db.Model(&existing).Updates(encryptedConsent).Error
}

func (r *EncryptedConsentRepository) GetConsentByTenant(tenantID string) (*models.Consent, error) {
	var encryptedConsent models.EncryptedConsent
	if err := r.db.Where("tenant_id = ?", tenantID).First(&encryptedConsent).Error; err != nil {
		return nil, err
	}
	return r.decryptConsent(&encryptedConsent)
}

func (r *EncryptedConsentRepository) GetConsentByUID(uid string) (*models.Consent, error) {
	var encryptedConsent models.EncryptedConsent
	if err := r.db.Where("id = ?", uid).First(&encryptedConsent).Error; err != nil {
		return nil, err
	}
	return r.decryptConsent(&encryptedConsent)
}

func (r *EncryptedConsentRepository) GetConsentHistory(uid, consentID string) ([]models.ConsentHistory, error) {
	var history []models.ConsentHistory
	if err := r.db.Where("consent_id = ?", consentID).Order("timestamp DESC").Find(&history).Error; err != nil {
		return nil, err
	}
	return history, nil
}

func (r *EncryptedConsentRepository) UpdateConsent(c *models.Consent, tenantID uuid.UUID) error {
	encryptedConsent, err := r.encryptConsent(c)
	if err != nil {
		return err
	}
	
	tenantSchema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		return err
	}
	
	return tenantDB.Model(&models.EncryptedConsent{}).Where("id = ? AND tenant_id = ?", c.ID, tenantID).Updates(encryptedConsent).Error
}

func (r *EncryptedConsentRepository) WithdrawConsentByPurpose(userID, tenantID, purposeID, consentID uuid.UUID) error {
	tenantSchema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		return err
	}

	// First, get the existing consent
	var encryptedConsent models.EncryptedConsent
	if err := tenantDB.Where("id = ? AND tenant_id = ?", consentID, tenantID).First(&encryptedConsent).Error; err != nil {
		return err
	}

	consent, err := r.decryptConsent(&encryptedConsent)
	if err != nil {
		return err
	}

	// Update the consent purposes to withdraw the specific purpose
	for i, purpose := range consent.Purposes.Purposes {
		if purpose.ID.String() == purposeID.String() {
			consent.Purposes.Purposes[i].Status = false
			break
		}
	}

	// Re-encrypt and update
	updatedEncryptedConsent, err := r.encryptConsent(consent)
	if err != nil {
		return err
	}

	return tenantDB.Model(&encryptedConsent).Updates(updatedEncryptedConsent).Error
}

func (r *EncryptedConsentRepository) CreateHistory(h *models.ConsentHistory, tenantID uuid.UUID) error {
	tenantSchema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		return err
	}

	return tenantDB.Create(h).Error
}

// DeleteConsent deletes a consent record by its ID and tenant ID.
func (r *EncryptedConsentRepository) DeleteConsent(consentID uuid.UUID, tenantID uuid.UUID) error {
	tenantSchema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		return err
	}

	result := tenantDB.Where("id = ? AND tenant_id = ?", consentID, tenantID).Delete(&models.EncryptedConsent{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrRecordNotFound
	}
	return nil
}

func (r *EncryptedConsentRepository) StoreHistory(h *models.ConsentHistory) error {
	return r.db.Create(h).Error
}

func (r *EncryptedConsentRepository) GetAllUserInTenant(tenantID uuid.UUID) ([]models.UserTenantLink, error) {
	var links []models.UserTenantLink
	if err := r.db.Where("tenant_id = ?", tenantID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

func (r *EncryptedConsentRepository) GetTenantConsentLogs(tenantID uuid.UUID) ([]models.ConsentHistory, error) {
	var logs []models.ConsentHistory
	if err := r.db.Where("tenant_id = ?", tenantID).Order("timestamp DESC").Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

func (r *EncryptedConsentRepository) LoadReviewTokenData(token string) (dto.ReviewPageData, error) {
	var rt models.ReviewToken
	if err := r.db.Where("token = ?", token).First(&rt).Error; err != nil {
		return dto.ReviewPageData{}, err
	}

	var encryptedConsent models.EncryptedConsent
	if err := r.db.Where("id = ?", rt.ID).First(&encryptedConsent).Error; err != nil {
		return dto.ReviewPageData{}, err
	}

	consent, err := r.decryptConsent(&encryptedConsent)
	if err != nil {
		return dto.ReviewPageData{}, err
	}

	return dto.ReviewPageData{
		UID:      consent.ID.String(),
		TenantID: consent.TenantID,
		Purposes: consent.Purposes.Purposes, // already unmarshalled
	}, nil
}

// ----------------------------- New ConsentLink methods -----------------------------

// CreateConsentLink creates a new consent link record.
func (r *EncryptedConsentRepository) CreateConsentLink(link *models.ConsentLink) error {
	if link.ID == uuid.Nil {
		link.ID = uuid.New()
	}
	link.CreatedAt = time.Now()
	link.UpdatedAt = time.Now()
	return r.db.Create(link).Error
}

// GetConsentLinkByID retrieves a consent link by ID.
func (r *EncryptedConsentRepository) GetConsentLinkByID(id uuid.UUID) (*models.ConsentLink, error) {
	var cl models.ConsentLink
	if err := r.db.First(&cl, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &cl, nil
}

// GetConsentLinkByLink retrieves a consent link by the link string.
func (r *EncryptedConsentRepository) GetConsentLinkByLink(linkStr string) (*models.ConsentLink, error) {
	var cl models.ConsentLink
	if err := r.db.First(&cl, "link = ?", linkStr).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &cl, nil
}

// UpdateConsentLink updates a consent link record.
func (r *EncryptedConsentRepository) UpdateConsentLink(link *models.ConsentLink) error {
	link.UpdatedAt = time.Now()
	return r.db.Save(link).Error
}

// DeleteConsentLink deletes a consent link by ID.
func (r *EncryptedConsentRepository) DeleteConsentLink(id uuid.UUID) error {
	return r.db.Delete(&models.ConsentLink{}, "id = ?", id).Error
}

// ListConsentLinksByTenant lists all consent links for a tenant.
func (r *EncryptedConsentRepository) ListConsentLinksByTenant(tenantID uuid.UUID) ([]models.ConsentLink, error) {
	var links []models.ConsentLink
	if err := r.db.Where("tenant_id = ?", tenantID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

// IncrementConsentSubmission increments submission_count atomically for a link ID.
func (r *EncryptedConsentRepository) IncrementConsentSubmission(id uuid.UUID) error {
	// Use a single UPDATE ... RETURNING to avoid race conditions and also to fetch the new count if needed.
	tx := r.db.Model(&models.ConsentLink{}).
		Where("id = ?", id).
		UpdateColumn("submission_count", gorm.Expr("submission_count + ?", 1))
	return tx.Error
}

// Optional: fetch with lock if you need to audit last_submitter, etc.
func (r *EncryptedConsentRepository) IncrementConsentSubmissionWithAudit(id uuid.UUID, lastSubmitter uuid.UUID) error {
	// Example: update count and set updated_at, use GORM's Clauses to perform an upsert or locking if needed.
	return r.db.Clauses(clause.Locking{Strength: "UPDATE"}).
		Model(&models.ConsentLink{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"submission_count": gorm.Expr("submission_count + ?", 1),
			"updated_at":       time.Now(),
		}).Error
}

func (r *EncryptedConsentRepository) encryptConsent(consent *models.Consent) (*models.EncryptedConsent, error) {
	encryptedConsent := &models.EncryptedConsent{
		ID:         consent.ID,
		UserID:     consent.UserID,
		TenantID:   consent.TenantID,
		GeoRegion:  consent.GeoRegion,
		Jurisdiction: consent.Jurisdiction,
		CreatedAt:  consent.CreatedAt,
		UpdatedAt:  consent.UpdatedAt,
	}

	// Encrypt sensitive fields
	if err := r.encryptStringField(consent.Signature, &encryptedConsent.Signature); err != nil {
		return nil, err
	}

	// Convert and encrypt PolicySnapshot
	if len(consent.PolicySnapshot) > 0 {
		policySnapshotStr := string(consent.PolicySnapshot)
		encryptedPolicySnapshot, err := encryption.Encrypt(policySnapshotStr)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt policy snapshot: %w", err)
		}
		encryptedConsent.PolicySnapshot = datatypes.JSON(encryptedPolicySnapshot)
	}

	// Convert and encrypt Purposes
	if len(consent.Purposes.Purposes) > 0 {
		purposesBytes, err := consent.Purposes.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal purposes: %w", err)
		}
		purposesStr := string(purposesBytes.([]byte))
		encryptedPurposes, err := encryption.Encrypt(purposesStr)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt purposes: %w", err)
		}
		encryptedConsent.Purposes = datatypes.JSON(encryptedPurposes)
	}

	return encryptedConsent, nil
}

func (r *EncryptedConsentRepository) decryptConsent(encryptedConsent *models.EncryptedConsent) (*models.Consent, error) {
	consent := &models.Consent{
		ID:          encryptedConsent.ID,
		UserID:      encryptedConsent.UserID,
		TenantID:    encryptedConsent.TenantID,
		GeoRegion:   encryptedConsent.GeoRegion,
		Jurisdiction: encryptedConsent.Jurisdiction,
		CreatedAt:   encryptedConsent.CreatedAt,
		UpdatedAt:   encryptedConsent.UpdatedAt,
	}

	// Decrypt sensitive fields
	var err error
	if consent.Signature, err = r.decryptStringField(encryptedConsent.Signature); err != nil {
		return nil, err
	}

	// Decrypt PolicySnapshot
	if len(encryptedConsent.PolicySnapshot) > 0 {
		policySnapshotStr, err := encryption.Decrypt(string(encryptedConsent.PolicySnapshot))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt policy snapshot: %w", err)
		}
		consent.PolicySnapshot = datatypes.JSON(policySnapshotStr)
	}

	// Decrypt Purposes
	if len(encryptedConsent.Purposes) > 0 {
		purposesStr, err := encryption.Decrypt(string(encryptedConsent.Purposes))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt purposes: %w", err)
		}
		var purposes dto.ConsentPurposes
		if err := purposes.Scan([]byte(purposesStr)); err != nil {
			return nil, fmt.Errorf("failed to unmarshal purposes: %w", err)
		}
		consent.Purposes = purposes
	}

	return consent, nil
}

func (r *EncryptedConsentRepository) encryptStringField(plaintext string, encryptedField *string) error {
	if plaintext == "" {
		*encryptedField = ""
		return nil
	}

	encrypted, err := encryption.Encrypt(plaintext)
	if err != nil {
		return err
	}
	*encryptedField = encrypted
	return nil
}

func (r *EncryptedConsentRepository) decryptStringField(encryptedText string) (string, error) {
	if encryptedText == "" {
		return "", nil
	}

	plaintext, err := encryption.Decrypt(encryptedText)
	if err != nil {
		return "", err
	}
	return plaintext, nil
}
