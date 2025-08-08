package repository

import (
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/models"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ConsentRepository struct {
	db *gorm.DB
}

func NewConsentRepository(db *gorm.DB) *ConsentRepository {
	return &ConsentRepository{db: db}
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
func (r *ConsentRepository) GetConsentByID(ctx context.Context, consentID uuid.UUID, tenantID uuid.UUID) (*models.Consent, error) {
	//get tenant DB based on tenant ID
	tenantSchema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		log.Printf("Error getting tenant DB for tenant %s: %v", tenantID, err)
		return nil, err
	}
	var consent models.Consent
	if err := tenantDB.Where("id = ? AND tenant_id = ?", consentID, tenantID).First(&consent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRecordNotFound // Consent not found
		}
		return nil, err // Other error
	}
	return &consent, nil // Successfully found consent
}

// Get all consents in a tenant (admin)
func (r *ConsentRepository) GetAllConsentsByTenant(tenantDB *gorm.DB, tenantID uuid.UUID) ([]models.Consent, error) {
	var consents []models.Consent
	err := tenantDB.Where("tenant_id = ?", tenantID).Find(&consents).Error
	return consents, err
}

// Get consent for a user in a tenant (admin)
func (r *ConsentRepository) GetUserConsentInTenant(tenantDB *gorm.DB, tenantID, userID uuid.UUID) (*models.Consent, error) {
	var consent models.Consent
	err := tenantDB.Where("tenant_id = ? AND user_id = ?", tenantID, userID).First(&consent).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &consent, err
}

func (r *ConsentRepository) GetPurposesByTenant(tenantID uuid.UUID) (dto.ConsentPurposes, error) {
	var consent models.Consent
	if err := r.db.Where("tenant_id = ?", tenantID).First(&consent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.ConsentPurposes{}, nil // No consent found for this tenant
		}
		log.Printf("Error fetching consent for tenant %s: %v", tenantID, err)
		return dto.ConsentPurposes{}, err
	}
	// Extract and return the actual slice of Purpose items
	return consent.Purposes, nil
}

func (r *ConsentRepository) UpsertConsent(consent *models.Consent) error {
	var existing models.Consent
	err := r.db.Where("uid = ?", consent.ID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if createErr := r.db.Create(consent).Error; createErr != nil {
			return createErr
		}
		return nil
	}
	if err != nil {
		return err
	}

	tenantID := existing.TenantID
	if existing.ID == uuid.Nil {
		existing.ID = uuid.New()
	}

	TenantDB := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(TenantDB)
	if err != nil {
		log.Printf("Error getting tenant DB for tenant %s: %v", tenantID, err)
		return err
	}
	auditLog := models.AuditLog{
		LogID:        uuid.New(),
		UserID:       existing.UserID,
		TenantID:     existing.TenantID,
		ActionType:   "Upsert Consent",
		Initiator:    "system",
		Timestamp:    time.Now(),
		Jurisdiction: "India",
	}
	if err := tenantDB.Create(&auditLog).Error; err != nil {
		log.Printf("Error creating audit log: %v", err)
		return err
	}
	return r.db.Save(&existing).Error
}

func (r *ConsentRepository) GetConsentByTenant(tenantID string) (*models.Consent, error) {
	var c models.Consent
	if err := r.db.Where("tenant_id = ?", tenantID).First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *ConsentRepository) GetConsentByUID(uid string) (*models.Consent, error) {
	var c models.Consent
	if err := r.db.Where("uid = ?", uid).First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *ConsentRepository) GetConsentHistory(uid, consentID string) ([]models.ConsentHistory, error) {
	var history []models.ConsentHistory
	log.Printf("Fetching consent history for UID: %s, Consent ID: %s", uid, consentID)
	if uid == "" || consentID == "" {
		return nil, errors.New("uid and consentID cannot be empty")
	}
	if err := r.db.Where("user_id = ? AND consent_id = ?", uid, consentID).Order("timestamp DESC").Find(&history).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("No consent history found for UID: %s, Consent ID: %s", uid, consentID)
			return nil, nil // No history found is not an error
		}
		log.Printf("Error fetching consent history for UID: %s, Consent ID: %s, Error: %v", uid, consentID, err)
		return nil, err
	}
	return history, nil
}

func (r *ConsentRepository) UpdateConsent(c *models.Consent, tenantID uuid.UUID) error {
	c.TenantID = tenantID
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}

	TenantDB := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(TenantDB)
	if err != nil {
		log.Printf("Error getting tenant DB for tenant %s: %v", tenantID, err)
		return err
	}
	if err := tenantDB.Save(c).Error; err != nil {
		log.Printf("Error updating consent for tenant %s: %v", tenantID, err)
		return err
	}
	log.Printf("Consent updated successfully for tenant %s", tenantID)
	auditLog := models.AuditLog{
		LogID:        uuid.New(),
		UserID:       c.UserID,
		TenantID:     c.TenantID,
		ActionType:   "Updated Consent",
		Initiator:    "system",
		Timestamp:    time.Now(),
		Jurisdiction: "India",
	}
	if err := tenantDB.Create(&auditLog).Error; err != nil {
		log.Printf("Error creating audit log: %v", err)
		return err
	}
	return nil
}

func (r *ConsentRepository) WithdrawConsentByPurpose(userID, tenantID, purposeID, consentID uuid.UUID) error {
	if userID == uuid.Nil || tenantID == uuid.Nil || purposeID == uuid.Nil || consentID == uuid.Nil {
		log.Println("Invalid parameters for withdrawing consent by purpose")
		return errors.New("userID, tenantID, purposeID, and consentID cannot be empty")
	}

	var consent models.Consent
	tenantSchema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		return fmt.Errorf("error getting tenant DB: %w", err)
	}

	if err := tenantDB.Where("id = ? AND user_id = ? AND tenant_id = ?", consentID, userID, tenantID).First(&consent).Error; err != nil {
		return fmt.Errorf("error fetching consent: %w", err)
	}

	found := false
	for i := range consent.Purposes.Purposes {
		if consent.Purposes.Purposes[i].ID == purposeID {
			consent.Purposes.Purposes[i].Status = false // Mark as withdrawn
			consent.Purposes.Purposes[i].Description = "Consent withdrawn by user"
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("purpose ID %s not found in consent", purposeID)
	}

	consent.UpdatedAt = time.Now()
	if err := tenantDB.Save(&consent).Error; err != nil {
		return fmt.Errorf("error updating consent: %w", err)
	}

	auditLog := models.AuditLog{
		LogID:        uuid.New(),
		UserID:       userID,
		TenantID:     tenantID,
		ActionType:   "Withdrawn Consent by Purpose",
		Initiator:    "system",
		Timestamp:    time.Now(),
		Jurisdiction: "India",
	}
	if err := tenantDB.Create(&auditLog).Error; err != nil {
		return fmt.Errorf("error creating audit log: %w", err)
	}

	return nil
}

func (r *ConsentRepository) CreateHistory(h *models.ConsentHistory, tenantID uuid.UUID) error {
	h.TenantID = tenantID
	if h.ID == uuid.Nil {
		h.ID = uuid.New()
	}

	TenantDB := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(TenantDB)
	if err != nil {
		log.Printf("Error getting tenant DB for tenant %s: %v", tenantID, err)
		return err
	}
	if err := tenantDB.Create(h).Error; err != nil {
		log.Printf("Error creating consent history for tenant %s: %v", tenantID, err)
		return err
	}
	log.Printf("Consent history created successfully for tenant %s", tenantID)
	auditLog := models.AuditLog{
		LogID:        uuid.New(),
		UserID:       h.UserID,
		TenantID:     h.TenantID,
		ActionType:   "Consent history Created",
		Initiator:    "system",
		Timestamp:    time.Now(),
		Jurisdiction: "India",
	}
	if err := tenantDB.Create(&auditLog).Error; err != nil {
		log.Printf("Error creating audit log: %v", err)
		return err
	}
	return nil
}

// DeleteConsent deletes a consent record by its ID and tenant ID.
func (r *ConsentRepository) DeleteConsent(consentID uuid.UUID, tenantID uuid.UUID) error {
	var consent models.Consent
	// Find the consent record by ID and tenant ID
	tenantSchema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(tenantSchema)
	if err != nil {
		log.Printf("Error getting tenant DB for tenant %s: %v", tenantID, err)
		return err
	}
	if err := tenantDB.Where("id = ? AND tenant_id = ?", consentID, tenantID).First(&consent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRecordNotFound // Consent not found
		}
		return err // Other error
	}

	// Delete the consent record
	if err := tenantDB.Delete(&consent).Error; err != nil {
		return err // Error during deletion
	}

	auditLog := models.AuditLog{
		LogID:        uuid.New(),
		UserID:       consent.UserID,
		TenantID:     consent.TenantID,
		ActionType:   "Deleted Consent",
		Initiator:    "system",
		Timestamp:    time.Now(),
		Jurisdiction: "India",
	}
	if err := tenantDB.Create(&auditLog).Error; err != nil {
		log.Printf("Error creating audit log: %v", err)
		return err
	}
	return nil // Successfully deleted
}

func (r *ConsentRepository) StoreHistory(h *models.ConsentHistory) error {
	return r.db.Create(h).Error
}

func ResolvePurposeID(db *gorm.DB, purposeName string) (uuid.UUID, error) {
	var purpose models.Purpose
	if err := db.Where("name = ?", purposeName).First(&purpose).Error; err != nil {
		return uuid.Nil, err
	}
	return purpose.ID, nil
}

// GetAllUserInTenant
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

	var consent models.Consent
	if err := r.db.Where("id = ?", rt.ID).First(&consent).Error; err != nil {
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