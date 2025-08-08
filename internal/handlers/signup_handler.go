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
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/log"
)

type AdminSignupRequest struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	Phone       string `json:"phone"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	Domain      string `json:"domain"`
	Industry    string `json:"industry"`
	CompanySize string `json:"companySize"`
}

type UserSignupRequest struct {
	Email         string `json:"email"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Age           int    `json:"age"`
	GuardianEmail string `json:"guardian_email,omitempty"`
	Location      string `json:"location"`
	Phone         string `json:"phone"`
	Password      string `json:"password"`
	Role          string `json:"role"` // dpo, developer, viewer

	// Permission flags (only relevant if Role = dpo)
	CanManageConsent   bool `json:"canManageConsent"`
	CanManageGrievance bool `json:"canManageGrievance"`
	CanManagePurposes  bool `json:"canManagePurposes"`
	CanManageAuditLogs bool `json:"canManageAuditLogs"`
}

type SignupHandler struct {
	MasterDB *gorm.DB
	Cfg      config.Config
}

func NewSignupHandler(masterDB *gorm.DB, cfg config.Config) *SignupHandler {
	return &SignupHandler{MasterDB: masterDB, Cfg: cfg}
}

// ========== ORG SIGNUP (SuperAdmin/Admin) ==========
func (h *SignupHandler) SignupOrganization(w http.ResponseWriter, r *http.Request) {
	var req AdminSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" || req.Role == "" || req.Name == "" ||
		req.Industry == "" || req.CompanySize == "" || req.Phone == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields")
		return
	}
	if !isValidEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
		return
	}
	if !isValidPhone(req.Phone) {
		writeError(w, http.StatusBadRequest, "Invalid phone number format (use +12-12345-67890)")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	tenantID := uuid.New()
	cluster := "us-east"

	// 1. Create master tenant row
	tenant := models.Tenant{
		TenantID:              tenantID,
		Name:                  req.Name,
		Domain:                req.Domain,
		Industry:              req.Industry,
		CompanySize:           req.CompanySize,
		ReviewFrequencyMonths: 6,
		CreatedAt:             time.Now(),
	}
	if err := h.MasterDB.Create(&tenant).Error; err != nil {
		log.Logger.Error().Err(err).Msg("Tenant creation failed")
		http.Error(w, "Tenant creation failed", http.StatusInternalServerError)
		return
	}

	// 2. Register cluster & create schema
	db.RegisterTenantCluster(tenantID, cluster)
	schema := "tenant_" + tenantID.String()[:8]
	clusterDB := db.Clusters[cluster]
	if err := clusterDB.Exec("CREATE SCHEMA IF NOT EXISTS " + schema).Error; err != nil {
		log.Logger.Error().Err(err).Msg("Schema creation failed")
		http.Error(w, "Schema creation failed", http.StatusInternalServerError)
		return
	}

	// 3. Run migrations in new schema
	if err := clusterDB.Exec("SET search_path TO "+schema).
		AutoMigrate(
			&models.TenantUser{},
			&models.Grievance{},
			&models.AuditLog{},
			&models.Consent{},
			&models.ConsentHistory{},
			&models.Purpose{},
			&models.DSRRequest{},
			&models.Notification{},
			&models.ReviewToken{},
		); err != nil {
		log.Logger.Error().Err(err).Msg("Migration failed")
		http.Error(w, "Migration failed", http.StatusInternalServerError)
		return
	}

	// 4. Hash password + create admin user
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Logger.Error().Err(err).Msg("Password hashing failed")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	admin := models.AdminUser{
		AdminID:      uuid.New(),
		TenantID:     tenantID,
		Role:         req.Role,
		Name:         req.Name,
		Phone:        req.Phone,
		Email:        req.Email,
		PasswordHash: string(hashed),
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
	}
	if err := db.MasterDB.Create(&admin).Error; err != nil {
		log.Logger.Error().Err(err).Msg("Admin user creation failed")
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tenant_id": tenantID,
		"user_id":   admin.AdminID,
		"message":   "Signup and tenant creation successful",
	})
}

// ========== USER SIGNUP (Only by SuperAdmin) ==========
func (h *SignupHandler) SignupUser(w http.ResponseWriter, r *http.Request) {
	// Require SuperAdmin to create users
	claims, ok := r.Context().Value(contextkeys.AdminClaimsKey).(*auth.AdminClaims)
	if !ok || claims.Role != "superadmin" {
		writeError(w, http.StatusForbidden, "Only super admin can create users")
		return
	}

	var req UserSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"message":"Invalid request"}`, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" || req.Phone == "" || req.Age <= 0 || req.Role == "" {
		http.Error(w, `{"message":"Missing required fields"}`, http.StatusBadRequest)
		return
	}
	if !isValidEmail(req.Email) {
		http.Error(w, `{"message":"Invalid email format"}`, http.StatusBadRequest)
		return
	}
	if !isValidPhone(req.Phone) {
		http.Error(w, `{"message":"Invalid phone number"}`, http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		http.Error(w, `{"message":"Password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}
	if req.Age < 18 {
		if req.GuardianEmail == "" || !isValidEmail(req.GuardianEmail) {
			http.Error(w, `{"message":"Guardian email required for users under 18"}`, http.StatusBadRequest)
			return
		}
	}

	// Encrypt password
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"message":"Internal error"}`, http.StatusInternalServerError)
		return
	}

	// Check for duplicates
	var existingUser models.MasterUser
	if err := h.MasterDB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		http.Error(w, `{"message":"Email already exists"}`, http.StatusBadRequest)
		return
	}
	var existingPhone models.MasterUser
	if err := h.MasterDB.Where("phone = ?", req.Phone).First(&existingPhone).Error; err == nil {
		http.Error(w, `{"message":"Phone already exists"}`, http.StatusBadRequest)
		return
	}

	// Create user
	user := models.MasterUser{
		UserID:             uuid.New(),
		Email:              req.Email,
		FirstName:          req.FirstName,
		LastName:           req.LastName,
		Age:                req.Age,
		Location:           req.Location,
		GuardianEmail:      req.GuardianEmail,
		Password:           string(hashed),
		Phone:              req.Phone,
		Role:               req.Role,
		CanManageConsent:   req.CanManageConsent,
		CanManageGrievance: req.CanManageGrievance,
		CanManagePurposes:  req.CanManagePurposes,
		CanManageAuditLogs: req.CanManageAuditLogs,
		CreatedAt:          time.Now(),
	}
	if err := h.MasterDB.Create(&user).Error; err != nil {
		http.Error(w, `{"message":"User creation failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": user.UserID,
		"message": "User signup successful. Please check your email for verification.",
	})
}

// ===== Helper validation functions =====
func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	return re.MatchString(email)
}
func isValidPhone(phone string) bool {
	re := regexp.MustCompile(`^\+\d{10,15}$`)
	return re.MatchString(phone)
}
