package services

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"consultrnr/consent-manager/internal/dto"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ConsentService struct {
	repo         *repository.ConsentRepository
	auditService *AuditService
}

type ConsentUpdateRequest struct {
	TenantID uuid.UUID
	Purposes []dto.Purpose
}

type AdminConsentOverride struct {
	UID      string
	Purposes []dto.Purpose
}

type ConsentReviewSubmission struct {
	Purposes []dto.Purpose
}

func NewConsentService(repo *repository.ConsentRepository, auditService *AuditService) *ConsentService {
	return &ConsentService{repo: repo, auditService: auditService}
}

func (s *ConsentService) Repo() *repository.ConsentRepository {
	return s.repo
}

func (s *ConsentService) SaveConsent(userID uuid.UUID, tenantID uuid.UUID, purposes []dto.Purpose) error {
	purposeBytes, err := json.Marshal(purposes)
	if err != nil {
		return err
	}

	var consentPurposes dto.ConsentPurposes
	err = json.Unmarshal(purposeBytes, &consentPurposes)
	if err != nil {
		log.Printf("Error unmarshalling purposes: %v", err)
		return fmt.Errorf("invalid consent purposes format: %w", err)
	}

	consent := models.Consent{
		UserID:   userID,
		Purposes: consentPurposes,
		TenantID: tenantID,
	}

	if err := s.repo.UpsertConsent(&consent); err != nil {
		log.Printf("Error upserting consent: %v", err)
		return err
	}

	history := models.ConsentHistory{
		ID:        uuid.New(),
		UserID:    userID,
		TenantID:  tenantID,
		Action:    "granted",
		Purposes:  purposeBytes,
		Timestamp: time.Now(),
	}
	_ = s.repo.DB().Create(&history)

	// Since this action can cover multiple purposes, we create a general audit log.
	// Specific purpose-level logs are created on granular updates.
	details := map[string]interface{}{
		"details":  "User consent saved/updated in bulk.",
		"purposes": purposes,
	}

	// For a bulk save, a nil PurposeID can be used.
	if err := s.auditService.Create(context.Background(), userID, tenantID, uuid.Nil, "CONSENT_SAVED", "", userID.String(), "system", "", "", details); err != nil {
		log.Printf("Error creating audit log for SaveConsent: %v", err)
		// Non-fatal error, just log it.
	}

	return nil
}

func (s *ConsentService) FetchConsentsByTenant(tenantID uuid.UUID) ([]dto.ConsentPurposes, error) {
	cp, err := s.repo.GetPurposesByTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return []dto.ConsentPurposes{cp}, nil
}

// GetVendorSharedConsents retrieves consents shared with a vendors
func (s *ConsentService) GetVendorSharedConsents(ctx context.Context, tenantDB *gorm.DB, tenantID uuid.UUID) ([]models.Consent, error) {
	if tenantID == uuid.Nil {
		return nil, errors.New("tenant ID cannot be nil")
	}

	consents, err := s.repo.GetAllConsentsByTenant(tenantDB, tenantID)
	if err != nil {
		log.Printf("Error fetching consents for tenant %s: %v", tenantID, err)
		return nil, fmt.Errorf("error fetching consents for tenant %s: %w", tenantID, err)
	}
	log.Printf("Found %d consents for tenant %s", len(consents), tenantID)
	return consents, nil
}

func (s *ConsentService) UpdateConsents(ctx context.Context, userID uuid.UUID, updates []ConsentUpdateRequest) error {
	for _, upd := range updates {
		purposeBytes, err := json.Marshal(upd.Purposes)
		if err != nil {
			return err
		}

		var consentPurposes dto.ConsentPurposes
		err = json.Unmarshal(purposeBytes, &consentPurposes)
		if err != nil {
			log.Printf("Error unmarshalling purposes: %v", err)
			return fmt.Errorf("invalid consent purposes format: %w", err)
		}
		consent := models.Consent{
			UserID:   userID,
			TenantID: upd.TenantID,
			Purposes: consentPurposes,
		}
		if err := s.repo.UpsertConsent(&consent); err != nil {
			return err
		}
		history := models.ConsentHistory{
			ID:        uuid.New(),
			UserID:    userID,
			TenantID:  upd.TenantID,
			Action:    "updated",
			Purposes:  purposeBytes,
			Timestamp: time.Now(),
		}
		_ = s.repo.CreateHistory(&history, upd.TenantID)

		tenantSchema := "tenant_" + upd.TenantID.String()[:8]
		tenantDB, err := db.GetTenantDB(tenantSchema)
		if err != nil {
			log.Printf("Error getting tenant DB for tenant %s: %v", upd.TenantID, err)
			return err
		}

		auditLog := models.AuditLog{
			LogID:        uuid.New(),
			UserID:       userID,
			TenantID:     upd.TenantID,
			ActionType:   "Upsert Consent",
			Initiator:    "system",
			Timestamp:    time.Now(),
			Jurisdiction: "India",
		}
		if err := tenantDB.Create(&auditLog).Error; err != nil {
			log.Printf("Error creating audit log: %v", err)
			return err
		}
	}
	return nil
}

// WithdrawConsentByPurpose
func (s *ConsentService) WithdrawConsentByPurpose(ctx context.Context, userID string, tenantID string, purposeID string, consentID string) error {
	if tenantID == "" {
		return errors.New("tenant ID cannot be empty")
	}
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if purposeID == "" && consentID == "" {
		return errors.New("purpose ID and consent ID cannot be empty")
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant ID format: %w", err)
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}
	if tenantUUID == uuid.Nil {
		return errors.New("tenant ID cannot be nil")
	}
	if userUUID == uuid.Nil {
		return errors.New("user ID cannot be nil")
	}
	purposeUUID := uuid.Nil
	if purposeID != "" {
		var err error
		purposeUUID, err = uuid.Parse(purposeID)
		if err != nil {
			log.Printf("Invalid purpose ID format: %s", purposeID)
			return errors.New("invalid purpose ID format")
		}
	}

	consentUUID, err := uuid.Parse(consentID)
	if err != nil {
		return fmt.Errorf("invalid consent ID format: %w", err)
	}

	if err := s.repo.WithdrawConsentByPurpose(userUUID, tenantUUID, purposeUUID, consentUUID); err != nil {
		log.Printf("Error withdrawing consent for user %s in tenant %s: %v", userID, tenantID, err)
		return fmt.Errorf("error withdrawing consent for user %s in tenant %s: %w", userID, tenantID, err)
	}

	return nil
}

// GetAllUserInTenant
func (s *ConsentService) GetAllUserInTenant(ctx context.Context, tenantID uuid.UUID) ([]models.UserTenantLink, error) {
	if tenantID == uuid.Nil {
		return nil, errors.New("tenant ID cannot be nil")
	}
	return s.repo.GetAllUserInTenant(tenantID)
}

func (s *ConsentService) GetAllUserConsents(ctx context.Context, userID uuid.UUID) ([]models.Consent, error) {
	return s.repo.GetUserConsents(s.repo.DB(), make(map[uuid.UUID]*gorm.DB), userID)
}

func (s *ConsentService) GetPurposes(ctx context.Context, tenantID uuid.UUID) ([]dto.ConsentPurpose, error) {
	if tenantID == uuid.Nil {
		return nil, errors.New("tenant ID cannot be nil")
	}
	cp, err := s.repo.GetPurposesByTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return cp.Purposes, nil
}

func (s *ConsentService) GetConsentHistory(ctx context.Context, userID uuid.UUID, consentID string) ([]models.ConsentHistory, error) {
	return s.repo.GetConsentHistory(userID.String(), consentID)
}

// List all consents for a tenant (admin)
func (s *ConsentService) GetAllConsentsByTenant(ctx context.Context, tenantDB *gorm.DB, tenantID uuid.UUID) ([]models.Consent, error) {
	return s.repo.GetAllConsentsByTenant(tenantDB, tenantID)
}

// Get a user's consent in a tenant (admin)
func (s *ConsentService) GetUserConsentInTenant(ctx context.Context, tenantDB *gorm.DB, tenantID, userID uuid.UUID) (*models.Consent, error) {
	return s.repo.GetUserConsentInTenant(tenantDB, tenantID, userID)
}

// GetUserByID retrieves a user by their UUID
func (s *ConsentService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.DataPrincipal, error) {
	var user models.DataPrincipal
	// This assumes a global user table, which is now deprecated.
	// We need to decide how to look up a user. For now, we'll assume a direct lookup
	// in a master user table if one exists, but this needs refactoring.
	if err := db.MasterDB.WithContext(ctx).First(&user, "id = ?", userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// Fetch user by email (for dashboard guardian flow)
func (s *ConsentService) GetUserByEmail(ctx context.Context, email string) (*models.DataPrincipal, error) {
	var user models.DataPrincipal
	if err := db.MasterDB.WithContext(ctx).First(&user, "email = ?", email).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// Initiate dashboard guardian approval (parent is a registered user)
func (s *ConsentService) InitiateGuardianDashboardApproval(ctx context.Context, minor *models.DataPrincipal, guardian *models.DataPrincipal, updates []ConsentUpdateRequest) error {
	updatesJSON, err := json.Marshal(updates)
	if err != nil {
		return err
	}
	pc := models.PendingConsent{
		ID:             uuid.New(),
		MinorUserID:    minor.ID,
		GuardianUserID: &guardian.ID,
		Updates:        updatesJSON,
		Status:         "pending",
	}
	if err := s.repo.DB().WithContext(ctx).Create(&pc).Error; err != nil {
		return err
	}
	// TODO: Send notification to guardian
	return nil
}

// Guardian approves/rejects in dashboard
func (s *ConsentService) ProcessGuardianDashboardApproval(ctx context.Context, guardianID string, pendingConsentID string, approve bool) error {
	var pc models.PendingConsent
	if err := s.repo.DB().WithContext(ctx).Where("id = ?", pendingConsentID).First(&pc).Error; err != nil {
		return err
	}
	if pc.GuardianUserID == nil || pc.GuardianUserID.String() != guardianID {
		return errors.New("not authorized")
	}
	if pc.Status != "pending" {
		return errors.New("already processed")
	}
	if approve {
		// Unmarshal updates and apply
		var updates []ConsentUpdateRequest
		if err := json.Unmarshal(pc.Updates, &updates); err != nil {
			return err
		}
		if err := s.UpdateConsents(ctx, pc.MinorUserID, updates); err != nil {
			return err
		}
		pc.Status = "approved"
	} else {
		pc.Status = "rejected"
	}
	pc.UpdatedAt = time.Now()
	return s.repo.DB().WithContext(ctx).Save(&pc).Error
}

// Initiate DigiLocker guardian flow (parent is not a user)
func (s *ConsentService) InitiateGuardianDigiLockerVerification(ctx context.Context, minor *models.DataPrincipal, updates []ConsentUpdateRequest) error {
	updatesJSON, err := json.Marshal(updates)
	if err != nil {
		return err
	}
	token := uuid.New().String() // Could use a more secure generator
	pc := models.PendingConsent{
		ID:             uuid.New(),
		MinorUserID:    minor.ID,
		GuardianUserID: nil, // DigiLocker
		Updates:        updatesJSON,
		Status:         "pending",
		Token:          token,
	}
	if err := s.repo.DB().WithContext(ctx).Create(&pc).Error; err != nil {
		return err
	}
	// TODO: Send DigiLocker link/token to the parent (SMS/email)
	fmt.Printf("[DIGILOCKER FLOW] Pending consent: %s, token: %s\n", pc.ID, token)
	return nil
}

// Generate DigiLocker link (for front-end to redirect)
func (s *ConsentService) GenerateDigiLockerLink(ctx context.Context, pendingConsentID string) (string, error) {
	var pc models.PendingConsent
	if err := s.repo.DB().WithContext(ctx).Where("id = ?", pendingConsentID).First(&pc).Error; err != nil {
		return "", err
	}
	cfg := config.LoadConfig()
	link := fmt.Sprintf("%s/verify?token=%s", cfg.DigiLockerBaseURL, pc.Token)
	return link, nil
}

// Called by DigiLocker after successful verification
func (s *ConsentService) ProcessDigiLockerCallback(ctx context.Context, token string, approve bool) error {
	var pc models.PendingConsent
	if err := s.repo.DB().WithContext(ctx).Where("token = ?", token).First(&pc).Error; err != nil {
		return err
	}
	if pc.Status != "pending" {
		return errors.New("already processed")
	}
	if approve {
		var updates []ConsentUpdateRequest
		if err := json.Unmarshal(pc.Updates, &updates); err != nil {
			return err
		}
		if err := s.UpdateConsents(ctx, pc.MinorUserID, updates); err != nil {
			return err
		}
		pc.Status = "approved"
	} else {
		pc.Status = "rejected"
	}
	pc.UpdatedAt = time.Now()
	return s.repo.DB().WithContext(ctx).Save(&pc).Error
}

// AdminOverrideConsent allows an admin to override user consents
func (s *ConsentService) AdminOverrideConsent(ctx context.Context, override AdminConsentOverride) error {
	// Parse the user ID
	userID, err := uuid.Parse(override.UID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	// For now, we'll use a default tenant ID
	// In a real implementation, this would be derived from the admin's context
	tenantID := uuid.Nil

	// Create consent update request
	updateReq := ConsentUpdateRequest{
		TenantID: tenantID,
		Purposes: override.Purposes,
	}

	// Update the consents
	if err := s.UpdateConsents(ctx, userID, []ConsentUpdateRequest{updateReq}); err != nil {
		return fmt.Errorf("failed to update consents: %w", err)
	}

	return nil
}

type ConsentLinkService struct {
	repo *repository.ConsentRepository
}

func NewConsentLinkService(repo *repository.ConsentRepository) *ConsentLinkService {
	return &ConsentLinkService{repo: repo}
}

func (s *ConsentLinkService) CreateLink(link *models.ConsentLink) error {
	link.CreatedAt = time.Now()
	link.UpdatedAt = time.Now()
	return s.repo.CreateConsentLink(link)
}

func (s *ConsentLinkService) GetLinkByID(id uuid.UUID) (*models.ConsentLink, error) {
	return s.repo.GetConsentLinkByID(id)
}

func (s *ConsentLinkService) GetLinkByURL(linkStr string) (*models.ConsentLink, error) {
	return s.repo.GetConsentLinkByLink(linkStr)
}

func (s *ConsentLinkService) UpdateLink(link *models.ConsentLink) error {
	link.UpdatedAt = time.Now()
	return s.repo.UpdateConsentLink(link)
}

func (s *ConsentLinkService) DeleteLink(id uuid.UUID) error {
	return s.repo.DeleteConsentLink(id)
}

func (s *ConsentLinkService) ListLinksByTenant(tid uuid.UUID) ([]models.ConsentLink, error) {
	return s.repo.ListConsentLinksByTenant(tid)
}

func (s *ConsentLinkService) IncrementSubmission(linkID uuid.UUID) error {
	return s.repo.IncrementConsentSubmission(linkID)
}
