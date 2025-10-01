package handlers

import (
	"encoding/json"
	"fmt"
	logger "log"
	"net/http"
	"regexp"
	"time"

	"consultrnr/consent-manager/internal/db"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/log"
)

type Organization struct {
	Name        string `json:"name"`
	Industry    string `json:"industry"`
	CompanySize string `json:"companySize"`
	TaxID       string `json:"taxId,omitempty"`
	Website     string `json:"website,omitempty"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
	Address     string `json:"address,omitempty"`
	Country     string `json:"country,omitempty"`
}

// FiduciarySignupRequest defines the shape of a signup request for a DF user.
// This user will manage a tenant and have specific permissions.
type FiduciarySignupRequest struct {
	Email        string       `json:"email"`
	FirstName    string       `json:"firstName"`
	LastName     string       `json:"lastName"`
	Phone        string       `json:"phone"`
	Password     string       `json:"password"`
	ConfirmPass  string       `json:"confirmPassword"`
	Role         string       `json:"role"`
	Organization Organization `json:"organization"`
}

// DataPrincipalSignupRequest defines the shape of a signup request for a DP user.
// This user is the data subject and is created by a Fiduciary.
type DataPrincipalSignupRequest struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	Age           int    `json:"age"`
	GuardianEmail string `json:"guardianEmail,omitempty"`
	Location      string `json:"location,omitempty"`
	Phone         string `json:"phone"`
}

type SignupHandler struct {
	MasterDB            *gorm.DB
	Cfg                 config.Config
	OrganizationService *services.OrganizationService
	EmailService        *services.EmailService
	AuditService        *services.AuditService
}

func NewSignupHandler(
	masterDB *gorm.DB,
	cfg config.Config,
	organizationService *services.OrganizationService, // Add this parameter
	emailService *services.EmailService,
	auditService *services.AuditService,
) *SignupHandler {
	return &SignupHandler{
		MasterDB:            masterDB,
		Cfg:                 cfg,
		OrganizationService: organizationService, // Assign the new parameter
		EmailService:        emailService,
		AuditService:        auditService,
	}
}

// SignupFiduciary handles the creation of a new tenant and its first admin user (a FiduciaryUser).
func (h *SignupHandler) SignupFiduciary(w http.ResponseWriter, r *http.Request) {
	var req FiduciarySignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Logger.Error().Err(err).Msg("Invalid request body for fiduciary signup")
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if !validateFiduciaryRequest(&req, w) {
		log.Logger.Error().Msg("Fiduciary signup validation failed")
		return
	}

	// Check for duplicate FiduciaryUser
	var existingUser models.FiduciaryUser
	if err := h.MasterDB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		log.Logger.Error().Str("email", req.Email).Msg("Fiduciary user already exists")
		writeError(w, http.StatusBadRequest, "A user with this email already exists")
		return
	}

	// Use a transaction for all critical steps
	err := h.MasterDB.Transaction(func(tx *gorm.DB) error {
		tenantID := uuid.New()
		cluster := "us-east" // TODO: Make this dynamic for multi-region

		tenant := models.Tenant{
			TenantID:    tenantID,
			Name:        req.Organization.Name,
			Industry:    req.Organization.Industry,
			CompanySize: req.Organization.CompanySize,
			CreatedAt:   time.Now(),
			Cluster:     cluster,
		}
		if err := tx.Create(&tenant).Error; err != nil {
			log.Logger.Error().Err(err).Msg("Failed to create tenant")
			return err
		}

		// Register cluster mapping
		if err := db.RegisterTenantCluster(tenantID, cluster); err != nil {
			log.Logger.Error().Err(err).Msg("Failed to register tenant cluster mapping")
			return err
		}

		schema := "tenant_" + tenantID.String()[:8]
		clusterDB, ok := db.Clusters[cluster]
		if !ok {
			log.Logger.Error().Str("cluster", cluster).Msg("Cluster not found")
			return fmt.Errorf("cluster not found")
		}
		if err := clusterDB.Exec("CREATE SCHEMA IF NOT EXISTS " + schema).Error; err != nil {
			log.Logger.Error().Err(err).Msg("Schema creation failed")
			return err
		}

		// Set search_path and migrate tables
		if err := clusterDB.Exec("SET search_path TO " + schema).Error; err != nil {
			log.Logger.Error().Err(err).Msg("Failed to set search_path")
			return err
		}
		if err := clusterDB.AutoMigrate(
			&models.Purpose{},
			&models.Consent{},
			&models.EncryptedConsent{},
			&models.ConsentForm{},
			&models.ConsentFormPurpose{},
			&models.ReviewToken{},
			&models.Grievance{},
			&models.GrievanceComment{},
			&models.BreachNotification{},
			&models.EncryptedBreachNotification{},
			&models.Vendor{},
			&models.DataProcessingAgreement{},
			&models.EncryptedDataProcessingAgreement{},
			&models.DPAComplianceCheck{},
			&models.DSRRequest{},
			&models.ConsentHistory{},
			&models.Notification{},
			&models.NotificationPreferences{},
			&models.APIKey{},
			&models.AuditLog{},
		); err != nil {
			log.Logger.Error().Err(err).Msg("Migration failed")
			return err
		}

		// Create OrganizationEntity
		org := models.OrganizationEntity{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Name:        req.Organization.Name,
			TaxID:       req.Organization.TaxID,
			Website:     req.Organization.Website,
			Email:       req.Organization.Email,
			Phone:       req.Organization.Phone,
			CompanySize: req.Organization.CompanySize,
			Industry:    req.Organization.Industry,
			Address:     req.Organization.Address,
			Country:     req.Organization.Country,
			CreatedAt:   time.Now(),
		}
		if err := h.OrganizationService.CreateOrganization(&org); err != nil {
			log.Logger.Error().Err(err).Msg("Failed to create organization")
			return err
		}

		// Create FiduciaryUser
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Logger.Error().Err(err).Msg("Failed to hash password")
			return err
		}

		// --- New RBAC Setup ---
		// 1. Get all available permissions
		var allPermissions []*models.Permission
		if err := tx.Find(&allPermissions).Error; err != nil {
			log.Logger.Error().Err(err).Msg("Failed to fetch all permissions for superadmin role")
			return err
		}

		// 2. Create the "Super Admin" role for this tenant
		superAdminRole := models.Role{
			ID:          uuid.New(),
			TenantID:    tenantID,
			Name:        "Super Admin",
			Description: "Full access to all features and settings.",
			Permissions: allPermissions,
		}
		if err := tx.Create(&superAdminRole).Error; err != nil {
			log.Logger.Error().Err(err).Msg("Failed to create superadmin role")
			return err
		}

		verificationToken := auth.GenerateSecureToken()
		fiduciary := models.FiduciaryUser{
			ID:                 uuid.New(),
			TenantID:           tenantID,
			Email:              req.Email,
			Name:               req.FirstName + " " + req.LastName,
			Phone:              req.Phone,
			PasswordHash:       string(hashedPassword),
			IsVerified:         false,
			VerificationToken:  verificationToken,
			VerificationExpiry: time.Now().Add(48 * time.Hour),
			Roles:              []*models.Role{&superAdminRole}, // Assign the new role
			// Deprecated fields - set for backward compatibility if needed
			Role: "superadmin",
		}
		if err := tx.Create(&fiduciary).Error; err != nil {
			log.Logger.Error().Err(err).Msg("Failed to create fiduciary user")
			return err
		}

		// Send verification email (do not fail transaction if email fails)
		go func() {
			verificationLink := h.Cfg.BaseURL + "/auth/verify-fiduciary?token=" + verificationToken
			emailBody := "Welcome! Please verify your account by clicking this link: " + verificationLink
			if err := h.EmailService.Send(req.Email, "Verify Your Account", emailBody); err != nil {
				log.Logger.Error().Err(err).Msg("Failed to send fiduciary verification email")
			}
		}()

		// Success: return tenant and fiduciary IDs
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"fiduciaryId": fiduciary.ID,
			"tenantId":    tenant.TenantID,
			"message":     "Organization and admin user created. Please check email for verification link.",
		})
		return nil
	})
	if err != nil {
		log.Logger.Error().Err(err).Msg("Fiduciary signup failed, rolling back")
		writeError(w, http.StatusInternalServerError, "Signup failed: "+err.Error())
		return
	}
}

// SignupDataPrincipal handles the creation of a new end-user (a DataPrincipal).
// This action is typically performed by an authenticated FiduciaryUser.
func (h *SignupHandler) SignupDataPrincipal(w http.ResponseWriter, r *http.Request) {
	var req DataPrincipalSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Check for duplicate DataPrincipal
	var existingUser models.DataPrincipal
	if err := h.MasterDB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		writeError(w, http.StatusBadRequest, "A user with this email already exists")
		return
	}
	tenantID := uuid.New() // Placeholder

	// Handle guardian verification for minors
	isGuardianRequired := req.Age > 0 && req.Age < 18
	var guardianToken string
	var guardianTokenExpiry time.Time
	if isGuardianRequired {
		if !isValidEmail(req.GuardianEmail) {
			writeError(w, http.StatusBadRequest, "A valid guardian email is required for minors")
			return
		}
		guardianToken = auth.GenerateSecureToken()
		guardianTokenExpiry = time.Now().Add(48 * time.Hour)
	}

	// Validate password
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "Password must be at least 8 characters long")
		return
	}

	// Hash the password with detailed logging
	logger.Printf("Hashing password for user: %s", req.Email)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Printf("Failed to hash password for user %s: %v", req.Email, err)
		writeError(w, http.StatusInternalServerError, "Failed to process password")
		return
	}
	logger.Printf("Successfully hashed password for user: %s", req.Email)

	// Create DataPrincipal with detailed logging
	dataPrincipal := models.DataPrincipal{
		ID:                         uuid.New(),
		TenantID:                   tenantID,
		Email:                      req.Email,
		FirstName:                  req.FirstName,
		LastName:                   req.LastName,
		Age:                        req.Age,
		Location:                   req.Location,
		Phone:                      req.Phone,
		PasswordHash:               string(hashedPassword),
		IsVerified:                 !isGuardianRequired, // Verified unless a guardian is needed
		IsGuardianVerified:         false,
		GuardianEmail:              req.GuardianEmail,
		GuardianVerificationToken:  guardianToken,
		GuardianVerificationExpiry: guardianTokenExpiry,
		CreatedAt:                  time.Now(),
		UpdatedAt:                  time.Now(),
	}

	// Log the data principal creation (without sensitive data)
	logger.Printf("Creating data principal: email=%s, first_name=%s, last_name=%s, age=%d, is_verified=%v",
		dataPrincipal.Email,
		dataPrincipal.FirstName,
		dataPrincipal.LastName,
		dataPrincipal.Age,
		dataPrincipal.IsVerified,
	)

	// Create the user in a transaction to ensure data consistency
	err = h.MasterDB.Transaction(func(tx *gorm.DB) error {
		// First create the user
		if err := tx.Create(&dataPrincipal).Error; err != nil {
			logger.Printf("Failed to create data principal in database: %v", err)
			return err
		}

		// Verify the password was stored correctly by reading it back
		var createdUser models.DataPrincipal
		if err := tx.Select("id", "email", "password_hash").
			Where("id = ?", dataPrincipal.ID).
			First(&createdUser).Error; err != nil {
			logger.Printf("Failed to verify created user: %v", err)
			return err
		}

		// Log the creation (without sensitive data)
		logger.Printf("Successfully created user %s with ID %s",
			createdUser.Email, createdUser.ID)

		return nil
	})

	if err != nil {
		logger.Printf("Transaction failed during user creation: %v", err)
		writeError(w, http.StatusInternalServerError, "Could not create user")
		return
	}

	// Audit logging for data principal creation
	if h.AuditService != nil {
		// Get tenant ID from context if available
		var tenantID uuid.UUID
		if ctxTenantID := r.Context().Value("tenant_id"); ctxTenantID != nil {
			if tid, ok := ctxTenantID.(string); ok {
				tenantID, _ = uuid.Parse(tid)
			}
		}

		// Get fiduciary ID from context if available
		var fiduciaryID uuid.UUID
		if ctxFiduciaryID := r.Context().Value("fiduciary_id"); ctxFiduciaryID != nil {
			if fid, ok := ctxFiduciaryID.(string); ok {
				fiduciaryID, _ = uuid.Parse(fid)
			}
		}

		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, dataPrincipal.ID, "data_principal_created", "created", "system", r.RemoteAddr, "", "", map[string]interface{}{
			"email":      dataPrincipal.Email,
			"first_name": dataPrincipal.FirstName,
			"last_name":  dataPrincipal.LastName,
			"age":        dataPrincipal.Age,
			"is_minor":   isGuardianRequired,
		})
	}

	// Send verification email to guardian if required
	if isGuardianRequired {
		verificationLink := h.Cfg.BaseURL + "/auth/verify-guardian?token=" + guardianToken
		emailBody := "Please verify the account for your child by clicking this link: " + verificationLink
		if err := h.EmailService.Send(req.GuardianEmail, "Verify Child's Account", emailBody); err != nil {
			log.Logger.Error().Err(err).Msg("Failed to send guardian verification email")
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"dataPrincipalId": dataPrincipal.ID,
		"message":         "Data principal created. If a minor, a verification email has been sent to the guardian.",
	})
}

// VerifyFiduciary handles the token-based verification for a new FiduciaryUser.
func (h *SignupHandler) VerifyFiduciary(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "Verification token is missing")
		return
	}

	var user models.FiduciaryUser
	if err := h.MasterDB.Where("verification_token = ?", token).First(&user).Error; err != nil {
		writeError(w, http.StatusNotFound, "Invalid or expired verification token")
		return
	}

	if time.Now().After(user.VerificationExpiry) {
		writeError(w, http.StatusBadRequest, "Verification token has expired")
		return
	}

	user.IsVerified = true
	user.VerificationToken = "" // Clear token after use
	if err := h.MasterDB.Save(&user).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update user verification status")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Account successfully verified."})
}

// VerifyGuardian handles token-based verification for a minor's guardian.
func (h *SignupHandler) VerifyGuardian(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "Verification token is missing")
		return
	}

	var user models.DataPrincipal
	if err := h.MasterDB.Where("guardian_verification_token = ?", token).First(&user).Error; err != nil {
		writeError(w, http.StatusNotFound, "Invalid or expired verification token")
		return
	}

	if time.Now().After(user.GuardianVerificationExpiry) {
		writeError(w, http.StatusBadRequest, "Verification token has expired")
		return
	}

	user.IsGuardianVerified = true
	user.IsVerified = true              // The user account is now fully active
	user.GuardianVerificationToken = "" // Clear token
	if err := h.MasterDB.Save(&user).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update user verification status")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Guardian verified. The user's account is now active."})
}

// ===== Helper validation functions =====
func validateFiduciaryRequest(req *FiduciarySignupRequest, w http.ResponseWriter) bool {
	if !isValidEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
		return false
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return false
	}
	if req.Organization.Name == "" || req.FirstName == "" || req.LastName == "" {
		writeError(w, http.StatusBadRequest, "Company and user name are required")
		return false
	}
	return true
}

func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	return re.MatchString(email)
}
