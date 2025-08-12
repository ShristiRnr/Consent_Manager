package repository

import (
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/models"
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ConsentRepository struct {
	db *gorm.DB
	encryptedRepo *EncryptedConsentRepository
}

func NewConsentRepository(db *gorm.DB) *ConsentRepository {
	return &ConsentRepository{db: db, encryptedRepo: NewEncryptedConsentRepository(db)}
}

func (r *ConsentRepository) DB() *gorm.DB {
	return r.db
}

func (r *ConsentRepository) GetUserConsents(masterDB *gorm.DB, tenantDBs map[uuid.UUID]*gorm.DB, userID uuid.UUID) ([]models.Consent, error) {
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
		consent, err := r.encryptedRepo.GetUserConsentInTenant(tenantDB, link.TenantID, userID)
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
func (r *ConsentRepository) GetConsentByID(ctx context.Context, consentID uuid.UUID, tenantID uuid.UUID) (*models.Consent, error) {
	return r.encryptedRepo.GetConsentByID(ctx, consentID, tenantID)
}

// Get all consents in a tenant (admin)
func (r *ConsentRepository) GetAllConsentsByTenant(tenantDB *gorm.DB, tenantID uuid.UUID) ([]models.Consent, error) {
	return r.encryptedRepo.GetAllConsentsByTenant(tenantDB, tenantID)
}

// Get consent for a user in a tenant (admin)
func (r *ConsentRepository) GetUserConsentInTenant(tenantDB *gorm.DB, tenantID, userID uuid.UUID) (*models.Consent, error) {
	return r.encryptedRepo.GetUserConsentInTenant(tenantDB, tenantID, userID)
}

func (r *ConsentRepository) GetPurposesByTenant(tenantID uuid.UUID) (dto.ConsentPurposes, error) {
	consents, err := r.encryptedRepo.GetAllConsentsByTenant(r.db, tenantID)
	if err != nil {
		return dto.ConsentPurposes{}, err
	}
	if len(consents) == 0 {
		return dto.ConsentPurposes{}, nil // No consent found for this tenant
	}
	// Extract and return the actual slice of Purpose items
	return consents[0].Purposes, nil
}

func (r *ConsentRepository) UpsertConsent(consent *models.Consent) error {
	return r.encryptedRepo.UpsertConsent(consent)
}

func (r *ConsentRepository) GetConsentByTenant(tenantID string) (*models.Consent, error) {
	consents, err := r.encryptedRepo.GetAllConsentsByTenant(r.db, uuid.MustParse(tenantID))
	if err != nil {
		return nil, err
	}
	if len(consents) == 0 {
		return nil, errors.New("no consent found for tenant")
	}
	return &consents[0], nil
}

func (r *ConsentRepository) GetConsentByUID(uid string) (*models.Consent, error) {
	// This method needs to search across all tenants since we don't have tenant ID
	// In a real implementation, you might want to store a mapping of consent UID to tenant ID
	return nil, errors.New("not implemented: requires tenant ID to retrieve consent by UID")
}

func (r *ConsentRepository) GetConsentHistory(uid, consentID string) ([]models.ConsentHistory, error) {
	var history []models.ConsentHistory
	if err := r.db.Where("consent_id = ?", consentID).Order("timestamp DESC").Find(&history).Error; err != nil {
		return nil, err
	}
	return history, nil
}

func (r *ConsentRepository) UpdateConsent(c *models.Consent, tenantID uuid.UUID) error {
	return r.encryptedRepo.UpdateConsent(c, tenantID)
}

func (r *ConsentRepository) WithdrawConsentByPurpose(userID, tenantID, purposeID, consentID uuid.UUID) error {
	return r.encryptedRepo.WithdrawConsentByPurpose(userID, tenantID, purposeID, consentID)
}

func (r *ConsentRepository) CreateHistory(h *models.ConsentHistory, tenantID uuid.UUID) error {
	tenantSchema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		return err
	}

	return tenantDB.Create(h).Error
}

// DeleteConsent deletes a consent record by its ID and tenant ID.
func (r *ConsentRepository) DeleteConsent(consentID uuid.UUID, tenantID uuid.UUID) error {
	return r.encryptedRepo.DeleteConsent(consentID, tenantID)
}

func (r *ConsentRepository) StoreHistory(h *models.ConsentHistory) error {
	return r.db.Create(h).Error
}

func (r *ConsentRepository) GetAllUserInTenant(tenantID uuid.UUID) ([]models.UserTenantLink, error) {
	var links []models.UserTenantLink
	if err := r.db.Where("tenant_id = ?", tenantID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

func (r *ConsentRepository) GetTenantConsentLogs(tenantID uuid.UUID) ([]models.ConsentHistory, error) {
	var logs []models.ConsentHistory
	if err := r.db.Where("tenant_id = ?", tenantID).Order("timestamp DESC").Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

func (r *ConsentRepository) LoadReviewTokenData(token string) (dto.ReviewPageData, error) {
	var rt models.ReviewToken
	if err := r.db.Where("token = ?", token).First(&rt).Error; err != nil {
		return dto.ReviewPageData{}, err
	}

	// Get tenant ID from the review token
	tenantID := rt.TenantID
	
	// Get consent by ID and tenant ID
	consent, err := r.encryptedRepo.GetConsentByID(context.Background(), rt.ID, tenantID)
	if err != nil {
		return dto.ReviewPageData{}, err
	}

	return dto.ReviewPageData{
		UID:      consent.ID.String(),
		TenantID: consent.TenantID,
		Purposes: consent.Purposes.Purposes, // already unmarshalled
	}, nil
}

// ErrRecordNotFound is a sentinel error that indicates that no record was found.
var ErrRecordNotFound = gorm.ErrRecordNotFound

// ----------------------------- New ConsentLink methods -----------------------------

// CreateConsentLink creates a new consent link record.
func (r *ConsentRepository) CreateConsentLink(link *models.ConsentLink) error {
	if link.ID == uuid.Nil {
		link.ID = uuid.New()
	}
	link.CreatedAt = time.Now()
	link.UpdatedAt = time.Now()
	return r.db.Create(link).Error
}

// GetConsentLinkByID retrieves a consent link by ID.
func (r *ConsentRepository) GetConsentLinkByID(id uuid.UUID) (*models.ConsentLink, error) {
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
func (r *ConsentRepository) GetConsentLinkByLink(linkStr string) (*models.ConsentLink, error) {
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
func (r *ConsentRepository) UpdateConsentLink(link *models.ConsentLink) error {
	link.UpdatedAt = time.Now()
	return r.db.Save(link).Error
}

// DeleteConsentLink deletes a consent link by ID.
func (r *ConsentRepository) DeleteConsentLink(id uuid.UUID) error {
	return r.db.Delete(&models.ConsentLink{}, "id = ?", id).Error
}

// ListConsentLinksByTenant lists all consent links for a tenant.
func (r *ConsentRepository) ListConsentLinksByTenant(tenantID uuid.UUID) ([]models.ConsentLink, error) {
	var links []models.ConsentLink
	if err := r.db.Where("tenant_id = ?", tenantID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

// IncrementConsentSubmission increments submission_count atomically for a link ID.
func (r *ConsentRepository) IncrementConsentSubmission(id uuid.UUID) error {
	// Use a single UPDATE ... RETURNING to avoid race conditions and also to fetch the new count if needed.
	tx := r.db.Model(&models.ConsentLink{}).
		Where("id = ?", id).
		UpdateColumn("submission_count", gorm.Expr("submission_count + ?", 1))
	return tx.Error
}

// Optional: fetch with lock if you need to audit last_submitter, etc.
func (r *ConsentRepository) IncrementConsentSubmissionWithAudit(id uuid.UUID, lastSubmitter uuid.UUID) error {
	// Example: update count and set updated_at, use GORM's Clauses to perform an upsert or locking if needed.
	return r.db.Clauses(clause.Locking{Strength: "UPDATE"}).
		Model(&models.ConsentLink{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"submission_count": gorm.Expr("submission_count + ?", 1),
			"updated_at":       time.Now(),
		}).Error
}