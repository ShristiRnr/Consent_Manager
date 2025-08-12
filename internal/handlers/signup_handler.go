package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/log"
)

// FiduciarySignupRequest defines the shape of a signup request for a DF user.
// This user will manage a tenant and have specific permissions.
type FiduciarySignupRequest struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	Phone       string `json:"phone"`
	Password    string `json:"password"`
	Role        string `json:"role"` // E.g., 'admin', 'dpo'
	CompanyName string `json:"companyName"`
	Domain      string `json:"domain"`
	Industry    string `json:"industry"`
	CompanySize string `json:"companySize"`
}

// DataPrincipalSignupRequest defines the shape of a signup request for a DP user.
// This user is the data subject and is created by a Fiduciary.
type DataPrincipalSignupRequest struct {
	Email         string `json:"email"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	Age           int    `json:"age"`
	GuardianEmail string `json:"guardianEmail,omitempty"`
	Location      string `json:"location,omitempty"`
	Phone         string `json:"phone"`
}

type SignupHandler struct {
	MasterDB     *gorm.DB
	Cfg          config.Config
	EmailService *services.EmailService
	AuditService *services.AuditService
}

func NewSignupHandler(masterDB *gorm.DB, cfg config.Config, emailService *services.EmailService, auditService *services.AuditService) *SignupHandler {
	return &SignupHandler{MasterDB: masterDB, Cfg: cfg, EmailService: emailService, AuditService: auditService}
}

// SignupFiduciary handles the creation of a new tenant and its first admin user (a FiduciaryUser).
func (h *SignupHandler) SignupFiduciary(w http.ResponseWriter, r *http.Request) {
	var req FiduciarySignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if !validateFiduciaryRequest(&req, w) {
		return
	}

	// Check for duplicate FiduciaryUser
	var existingUser models.FiduciaryUser
	if err := h.MasterDB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		writeError(w, http.StatusBadRequest, "A user with this email already exists")
		return
	}

	// Create Tenant
	tenantID := uuid.New()
	tenant := models.Tenant{
		TenantID:    tenantID,
		Name:        req.CompanyName,
		Domain:      req.Domain,
		Industry:    req.Industry,
		CompanySize: req.CompanySize,
		CreatedAt:   time.Now(),
	}
	if err := h.MasterDB.Create(&tenant).Error; err != nil {
		log.Logger.Error().Err(err).Msg("Failed to create tenant")
		writeError(w, http.StatusInternalServerError, "Could not create organization")
		return
	}

	// Create FiduciaryUser
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to process password")
		return
	}

	verificationToken := auth.GenerateSecureToken()
	fiduciary := models.FiduciaryUser{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Email:              req.Email,
		Name:               req.Name,
		Phone:              req.Phone,
		PasswordHash:       string(hashedPassword),
		Role:               req.Role,
		IsVerified:         false,
		VerificationToken:  verificationToken,
		VerificationExpiry: time.Now().Add(48 * time.Hour),
	}
	if err := h.MasterDB.Create(&fiduciary).Error; err != nil {
		log.Logger.Error().Err(err).Msg("Failed to create fiduciary user")
		writeError(w, http.StatusInternalServerError, "Could not create user account")
		return
	}

	// Send verification email
	verificationLink := h.Cfg.BaseURL + "/auth/verify-fiduciary?token=" + verificationToken
	emailBody := "Welcome! Please verify your account by clicking this link: " + verificationLink
	if err := h.EmailService.Send(req.Email, "Verify Your Account", emailBody); err != nil {
		log.Logger.Error().Err(err).Msg("Failed to send fiduciary verification email")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"fiduciaryId": fiduciary.ID,
		"tenantId":    tenant.TenantID,
		"message":     "Organization and admin user created. Please check email for verification link.",
	})
}

// SignupDataPrincipal handles the creation of a new end-user (a DataPrincipal).
// This action is typically performed by an authenticated FiduciaryUser.
func (h *SignupHandler) SignupDataPrincipal(w http.ResponseWriter, r *http.Request) {
	var req DataPrincipalSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// For now, we'll assume the tenant comes from the authenticated fiduciary user's context.
	// This needs to be implemented properly with middleware.
	// tenantID, ok := r.Context().Value(contextkeys.TenantIDKey).(uuid.UUID)
	// if !ok {
	// 	writeError(w, http.StatusUnauthorized, "Could not identify tenant from authenticated user")
	// 	return
	// }
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

	// Create DataPrincipal
	dataPrincipal := models.DataPrincipal{
		ID:                         uuid.New(),
		TenantID:                   tenantID,
		Email:                      req.Email,
		FirstName:                  req.FirstName,
		LastName:                   req.LastName,
		Age:                        req.Age,
		Location:                   req.Location,
		Phone:                      req.Phone,
		IsVerified:                 !isGuardianRequired, // Verified unless a guardian is needed
		IsGuardianVerified:         false,
		GuardianEmail:              req.GuardianEmail,
		GuardianVerificationToken:  guardianToken,
		GuardianVerificationExpiry: guardianTokenExpiry,
	}

	if err := h.MasterDB.Create(&dataPrincipal).Error; err != nil {
		log.Logger.Error().Err(err).Msg("Failed to create data principal")
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
	if req.CompanyName == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "Company and user name are required")
		return false
	}
	return true
}

func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	return re.MatchString(email)
}
