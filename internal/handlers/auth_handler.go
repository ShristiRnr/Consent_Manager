package handlers

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/claims"
	contextKey "consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/log"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	logger "log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token              string   `json:"token"`
	UserID             string   `json:"userId"`
	Email              string   `json:"email"`
	Phone              string   `json:"phone"`
	Tenants            []string `json:"tenants,omitempty"`
	Role               string   `json:"role"`
	CanManageConsent   bool     `json:"canManageConsent,omitempty"`
	CanManageGrievance bool     `json:"canManageGrievance,omitempty"`
	CanManagePurposes  bool     `json:"canManagePurposes,omitempty"`
	CanManageAuditLogs bool     `json:"canManageAuditLogs,omitempty"`
	ExpiresIn          int64    `json:"expiresIn"`
}

type FiduciaryLoginResponse struct {
	Token       string          `json:"token"`
	FiduciaryID string          `json:"fiduciaryId"`
	Email       string          `json:"email"`
	Phone       string          `json:"phone"`
	TenantID    string          `json:"tenantId"`
	ExpiresIn   int64           `json:"expiresIn"`
	Roles       []string        `json:"roles"`
	Permissions map[string]bool `json:"permissions"`
	Role        string          `json:"role"` // Deprecated
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

// ===== FIDUCIARY AUTH HANDLERS =====

func FiduciaryLoginHandler(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		if req.Email == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "email and password required")
			return
		}

		var fiduciary models.FiduciaryUser
		if err := db.Where("LOWER(email) = ?", strings.ToLower(req.Email)).First(&fiduciary).Error; err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(fiduciary.PasswordHash), []byte(req.Password)); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Preload roles and permissions to include them in the JWT
		if err := db.Preload("Roles.Permissions").Where("LOWER(email) = ?", strings.ToLower(req.Email)).First(&fiduciary).Error; err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		accessToken, err := auth.GenerateFiduciaryToken(fiduciary, privateKey, cfg.AdminTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		// For refresh token, we don't need to preload all permissions again
		var fiduciaryForRefresh models.FiduciaryUser
		db.Preload("Roles").Where("id = ?", fiduciary.ID).First(&fiduciaryForRefresh)

		refreshToken, err := auth.GenerateFiduciaryRefreshToken(fiduciaryForRefresh, privateKey, cfg.AdminRefreshTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "fiduciary_refresh_token",
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(cfg.AdminRefreshTokenTTL.Seconds()),
		})

		roleNames := []string{}
		permissions := make(map[string]bool)
		for _, role := range fiduciary.Roles {
			roleNames = append(roleNames, role.Name)
			for _, p := range role.Permissions {
				permissions[p.Name] = true
			}
		}

		resp := FiduciaryLoginResponse{
			Token:       accessToken,
			FiduciaryID: fiduciary.ID.String(),
			Email:       fiduciary.Email,
			Phone:       fiduciary.Phone,
			TenantID:    fiduciary.TenantID.String(),
			ExpiresIn:   int64(cfg.AdminTokenTTL.Seconds()),
			Roles:       roleNames,
			Permissions: permissions,
			Role:        fiduciary.Role, // Keep for backward compatibility if needed
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// -------------------------
// Superadmin Creates User
// -------------------------

type CreateUserRequest struct {
	Email     string      `json:"email"`
	Phone     string      `json:"phone"`
	Password  string      `json:"password"`
	FirstName string      `json:"firstName"`
	LastName  string      `json:"lastName"`
	RoleIDs   []uuid.UUID `json:"roleIds"` // Assign roles by their IDs
}

func FiduciaryCreateUserHandler(db *gorm.DB, auditService *services.AuditService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextKey.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
		if !ok {
			writeError(w, http.StatusForbidden, "fiduciary access required")
			return
		}

		var req CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		var existingUser models.FiduciaryUser
		if err := db.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
			writeError(w, http.StatusConflict, "email already in use")
			return
		}

		// Find the roles to be assigned from the database
		var rolesToAssign []*models.Role
		if len(req.RoleIDs) > 0 {
			if err := db.Where("id IN ? AND tenant_id = ?", req.RoleIDs, claims.TenantID).Find(&rolesToAssign).Error; err != nil {
				writeError(w, http.StatusBadRequest, "one or more role IDs are invalid")
				return
			}
		}

		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		newUser := models.FiduciaryUser{
			ID:           uuid.New(),
			TenantID:     uuid.MustParse(claims.TenantID),
			Email:        req.Email,
			Phone:        req.Phone,
			PasswordHash: string(hash),
			Name:         req.FirstName + " " + req.LastName,
			Roles:        rolesToAssign,
		}

		if err := db.Create(&newUser).Error; err != nil {
			log.Logger.Error().Err(err).Msg("failed to create user")
			writeError(w, http.StatusInternalServerError, "failed to create user")
			return
		}

		// Audit logging for fiduciary user creation
		if auditService != nil {
			fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go auditService.Create(r.Context(), fiduciaryID, tenantID, newUser.ID, "fiduciary_user_created", "created", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"email": newUser.Email,
				"name":  newUser.Name,
				"roles": req.RoleIDs,
			})
		}

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"message": "user created successfully",
			"userId":  newUser.ID,
		})
	}
}

func ImpersonateUserHandler(db *gorm.DB, auditService *services.AuditService, privateKey *rsa.PrivateKey, ttl time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Get the admin/superuser performing the action
		impersonatorClaims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if impersonatorClaims == nil {
			writeError(w, http.StatusUnauthorized, "Fiduciary claims not found")
			return
		}

		// 2. Get the ID of the user to be impersonated from the URL
		vars := mux.Vars(r)
		targetUserID, err := uuid.Parse(vars["userId"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid user ID format")
			return
		}

		// 3. Fetch the target user from the database, ensuring they are in the same tenant
		var targetUser models.FiduciaryUser
		if err := db.Preload("Roles.Permissions").
			Where("id = ? AND tenant_id = ?", targetUserID, impersonatorClaims.TenantID).
			First(&targetUser).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				writeError(w, http.StatusNotFound, "User not found in this tenant")
				return
			}
			writeError(w, http.StatusInternalServerError, "Failed to retrieve user")
			return
		}

		// 4. Generate a special impersonation token
		impersonationToken, err := auth.GenerateFiduciaryImpersonationToken(targetUser, impersonatorClaims.FiduciaryID, privateKey, ttl)
		if err != nil {
			log.Logger.Error().Err(err).Msg("Failed to generate impersonation token")
			writeError(w, http.StatusInternalServerError, "Could not create impersonation session")
			return
		}

		// Audit the impersonation event
		if auditService != nil {
			// Fetch the impersonator's details to get their email for the audit log.
			var impersonatorUser models.FiduciaryUser
			db.Where("id = ?", impersonatorClaims.FiduciaryID).First(&impersonatorUser)

			impersonatorID, _ := uuid.Parse(impersonatorClaims.FiduciaryID)
			tenantID, _ := uuid.Parse(impersonatorClaims.TenantID)
			go auditService.Create(r.Context(), impersonatorID, tenantID, targetUser.ID, "fiduciary_impersonation_started", "started", impersonatorClaims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"impersonator_email":      impersonatorUser.Email,
				"impersonated_user_id":    targetUser.ID.String(),
				"impersonated_user_email": targetUser.Email,
			})
		}

		// 5. Create the response payload, including the new token and impersonation context
		roleNames := []string{}
		permissions := make(map[string]bool)
		for _, role := range targetUser.Roles {
			roleNames = append(roleNames, role.Name)
			for _, p := range role.Permissions {
				permissions[p.Name] = true
			}
		}

		resp := FiduciaryLoginResponse{
			Token:       impersonationToken,
			FiduciaryID: targetUser.ID.String(),
			Email:       targetUser.Email,
			Phone:       targetUser.Phone,
			TenantID:    targetUser.TenantID.String(),
			ExpiresIn:   int64(ttl.Seconds()),
			Roles:       roleNames,
			Permissions: permissions,
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

func UserMeHandler(db *gorm.DB, auditService *services.AuditService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextKey.UserClaimsKey).(*claims.DataPrincipalClaims)
		if !ok {
			writeError(w, http.StatusForbidden, "user access required")
			return
		}

		var user models.DataPrincipal
		if err := db.Where("id = ?", claims.ID).First(&user).Error; err != nil {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}

		// Audit logging for data principal access
		if auditService != nil {
			userID, _ := uuid.Parse(claims.ID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go auditService.Create(r.Context(), userID, tenantID, userID, "data_principal_accessed", "accessed", claims.ID, r.RemoteAddr, "", "", map[string]interface{}{
				"email": user.Email,
			})
		}

		writeJSON(w, http.StatusOK, user)
	}
}

func UpdateUserHandler(db *gorm.DB, auditService *services.AuditService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextKey.UserClaimsKey).(*claims.DataPrincipalClaims)
		if !ok {
			writeError(w, http.StatusForbidden, "user access required")
			return
		}

		var user models.DataPrincipal
		if err := db.Where("id = ?", claims.ID).First(&user).Error; err != nil {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}

		var req models.DataPrincipal
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		// Update fields
		if req.FirstName != "" {
			user.FirstName = req.FirstName
		}
		if req.LastName != "" {
			user.LastName = req.LastName
		}
		if req.Phone != "" {
			user.Phone = req.Phone
		}
		if req.Location != "" {
			user.Location = req.Location
		}

		if err := db.Save(&user).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update user")
			return
		}

		// Audit logging for data principal update
		if auditService != nil {
			userID, _ := uuid.Parse(claims.ID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go auditService.Create(r.Context(), userID, tenantID, userID, "data_principal_updated", "updated", claims.ID, r.RemoteAddr, "", "", map[string]interface{}{
				"email": user.Email,
			})
		}

		writeJSON(w, http.StatusOK, map[string]string{"message": "user updated"})
	}
}

func UserLogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "user_refresh_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message": "logged out",
		})
	}
}

func FiduciaryMeHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fiduciary, err := GetFiduciaryData(db, r.Context())
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				writeError(w, http.StatusNotFound, "fiduciary not found")
				return
			}
			log.Logger.Error().Err(err).Msg("failed to fetch fiduciary data")
			writeError(w, http.StatusInternalServerError, "failed to fetch fiduciary data")
			return
		}

		writeJSON(w, http.StatusOK, fiduciary)
	}
}

func GetFiduciaryData(db *gorm.DB, ctx context.Context) (*models.FiduciaryUser, error) {
	claims := middlewares.GetFiduciaryAuthClaims(ctx)
	if claims == nil {
		return nil, gorm.ErrRecordNotFound
	}

	var fiduciary models.FiduciaryUser
	if err := db.Where("id = ?", claims.FiduciaryID).First(&fiduciary).Error; err != nil {
		return nil, err
	}
	return &fiduciary, nil
}

func GetFiduciaryByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var fiduciary models.FiduciaryUser
		fiduciaryID := r.Header.Get("fiduciary_id")
		if err := db.MasterDB.Where("id = ?", fiduciaryID).First(&fiduciary).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				writeError(w, http.StatusNotFound, "fiduciary not found")
				return
			}
			log.Logger.Error().Err(err).Msg("failed to fetch fiduciary data")
			writeError(w, http.StatusInternalServerError, "failed to fetch fiduciary data")
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"fiduciary_id": fiduciary.ID,
			"tenant_id":    fiduciary.TenantID,
			"email":        fiduciary.Email,
			"phone":        fiduciary.Phone,
			"name":         fiduciary.Name,
			"created_at":   fiduciary.CreatedAt,
			"role":         fiduciary.Role,
		})
	}
}

func FiduciaryRefreshHandler(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("fiduciary_refresh_token")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "missing fiduciary refresh token")
			return
		}
		claims, err := auth.ParseFiduciaryRefreshToken(cookie.Value, publicKey)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid fiduciary refresh token")
			return
		}

		// To generate a new token, we need the full fiduciary object.
		var fiduciary models.FiduciaryUser
		fiduciaryID, err := uuid.Parse(claims.FiduciaryID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if err := db.Where("id = ?", fiduciaryID).First(&fiduciary).Error; err != nil {
			writeError(w, http.StatusUnauthorized, "fiduciary not found")
			return
		}

		accessToken, err := auth.GenerateFiduciaryToken(fiduciary, privateKey, cfg.AdminTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"token":     accessToken,
			"expiresIn": int64(cfg.AdminTokenTTL.Seconds()),
		})
	}
}

func FiduciaryLogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "fiduciary_refresh_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message": "fiduciary logged out",
		})
	}
}

func FiduciaryForgotPasswordHandler(db *gorm.DB, emailSender func(to, token string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ForgotPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		var fiduciary models.FiduciaryUser
		if err := db.Where("email = ?", req.Email).First(&fiduciary).Error; err != nil {
			// Do not reveal whether the user exists or not.
			log.Logger.Info().Str("email", req.Email).Msg("Password reset requested for non-existent fiduciary")
			writeJSON(w, http.StatusOK, map[string]string{"message": "if user exists, an email will be sent"})
			return
		}

		resetToken := uuid.New().String()
		resetExpiry := time.Now().Add(30 * time.Minute)
		fiduciary.PasswordResetToken = resetToken
		fiduciary.PasswordResetExpiry = resetExpiry
		db.Save(&fiduciary)

		// In a real app, this should be a background job
		go emailSender(fiduciary.Email, resetToken)

		writeJSON(w, http.StatusOK, map[string]string{"message": "if user exists, an email will be sent"})
	}
}

func FiduciaryResetPasswordHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		var fiduciary models.FiduciaryUser
		if err := db.Where("password_reset_token = ?", req.Token).First(&fiduciary).Error; err != nil {
			writeError(w, http.StatusBadRequest, "invalid or expired token")
			return
		}

		if fiduciary.PasswordResetExpiry.IsZero() || fiduciary.PasswordResetToken == "" || fiduciary.PasswordResetExpiry.Before(time.Now()) {
			writeError(w, http.StatusBadRequest, "invalid or expired token")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update password")
			return
		}

		fiduciary.PasswordHash = string(hashedPassword)
		fiduciary.PasswordResetToken = ""
		fiduciary.PasswordResetExpiry = time.Time{}
		db.Save(&fiduciary)

		writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
	}
}

// ===== USER AUTH HANDLERS =====

// UserLoginRequest represents the request body for user login
type UserLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UserLoginResponse represents the response body for user login
type UserLoginResponse struct {
	Token     string `json:"token"`
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	TenantID  string `json:"tenantId"`
	ExpiresIn int64  `json:"expiresIn"`
}

// UserLoginHandler handles user login requests
func UserLoginHandler(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req UserLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		if req.Email == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "email and password required")
			return
		}

		var user models.DataPrincipal
		// First check if user exists with debug logging
		logger.Printf("Debug - Attempting to find user with email: %s", req.Email)

		// Explicitly select only the fields we need
		result := db.Select(
			"id", "email", "password_hash", "is_verified", "tenant_id", "phone",
		).Where("LOWER(email) = LOWER(?)", req.Email).First(&user)

		if result.Error != nil {
			logger.Printf("Error finding user: %v", result.Error)
			writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}

		// Log user details for debugging
		logger.Printf("Debug - Found user - ID: %s, Email: %s, Has PasswordHash: %v, Is Verified: %v",
			user.ID, user.Email, user.PasswordHash != "", user.IsVerified)

		if user.PasswordHash == "" {
			logger.Printf("Error - Empty PasswordHash for user: %s (ID: %s)", user.Email, user.ID)
			writeError(w, http.StatusUnauthorized, "account setup not completed. Please reset your password.")
			return
		}

		// Check if account is verified
		if !user.IsVerified {
			logger.Printf("Error - Account not verified for user: %s", user.Email)
			writeError(w, http.StatusForbidden, "account not verified. Please check your email.")
			return
		}

		// Debug: Check if bcrypt can parse the hash
		_, err := bcrypt.Cost([]byte(user.PasswordHash))
		if err != nil {
			logger.Printf("Error - Invalid bcrypt hash for user %s: %v", user.Email, err)
			writeError(w, http.StatusInternalServerError, "authentication error")
			return
		}

		// Now compare the password
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid Password")
			return
		}

		accessToken, err := auth.GenerateDataPrincipalToken(user, privateKey, cfg.UserTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		refreshToken, err := auth.GenerateDataPrincipalRefreshToken(user, privateKey, cfg.UserRefreshTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "user_refresh_token",
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(cfg.UserRefreshTokenTTL.Seconds()),
		})

		// For DataPrincipal, we only include basic user info in the response
		resp := UserLoginResponse{
			Token:     accessToken,
			UserID:    user.ID.String(),
			Email:     user.Email,
			Phone:     user.Phone,
			TenantID:  user.TenantID.String(),
			ExpiresIn: int64(cfg.UserTokenTTL.Seconds()),
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// UserForgotPasswordHandler handles user forgot password requests
func UserForgotPasswordHandler(db *gorm.DB, emailSender func(to, token string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		var req ForgotPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Printf("Error decoding forgot password request: %v", err)
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		// Validate email
		if req.Email == "" {
			writeError(w, http.StatusBadRequest, "email is required")
			return
		}

		logger.Printf("Password reset requested for email: %s", req.Email)

		// Find user by email (case-insensitive)
		var user models.DataPrincipal
		if err := db.Where("LOWER(email) = LOWER(?)", req.Email).First(&user).Error; err != nil {
			// For security, don't reveal if the user exists or not
			logger.Printf("Password reset requested for non-existent or unverified email: %s", req.Email)
			// Return success to prevent user enumeration
			writeJSON(w, http.StatusOK, map[string]string{"message": "If an account exists with this email, a password reset link has been sent"})
			return
		}

		// Generate secure random token
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err != nil {
			logger.Printf("Error generating reset token: %v", err)
			writeError(w, http.StatusInternalServerError, "error generating reset token")
			return
		}
		resetToken := hex.EncodeToString(tokenBytes)

		// Set token and expiry (30 minutes from now)
		resetExpiry := time.Now().Add(30 * time.Minute)

		// Update user with reset token
		result := db.Model(&models.DataPrincipal{}).
			Where("id = ?", user.ID).
			Updates(map[string]interface{}{
				"password_reset_token":  resetToken,
				"password_reset_expiry": resetExpiry,
			})

		if result.Error != nil {
			logger.Printf("Error updating user with reset token: %v", result.Error)
			writeError(w, http.StatusInternalServerError, "error initiating password reset")
			return
		}

		// Log the reset token for development purposes
		logger.Printf("Password reset token for %s: %s", user.Email, resetToken)

		// Send reset email (in background)
		go func(email, token string) {
			// In a real app, you would generate a proper reset link
			resetLink := fmt.Sprintf("https://yourapp.com/reset-password?token=%s", token)
			emailBody := fmt.Sprintf("To reset your password, click the following link: %s\n\n"+
				"This link will expire in 30 minutes.\n"+
				"If you didn't request this, please ignore this email.", resetLink)

			if err := emailSender(email, emailBody); err != nil {
				logger.Printf("Error sending password reset email to %s: %v", email, err)
			}
		}(user.Email, resetToken)

		// Return success response
		writeJSON(w, http.StatusOK, map[string]string{
			"message": "If an account exists with this email, a password reset link has been sent",
		})
	}
}

// UserResetPasswordHandler handles user password reset requests
func UserResetPasswordHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		var req ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Printf("Error decoding reset password request: %v", err)
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		// Validate request
		if req.Token == "" || req.NewPassword == "" {
			writeError(w, http.StatusBadRequest, "token and new password are required")
			return
		}

		// Validate password strength
		if len(req.NewPassword) < 8 {
			writeError(w, http.StatusBadRequest, "password must be at least 8 characters long")
			return
		}

		logger.Printf("Password reset attempt with token: %s", req.Token)

		// Find user by token and check expiry
		var user models.DataPrincipal
		err := db.Where("password_reset_token = ?", req.Token).First(&user).Error
		if err != nil {
			logger.Printf("Invalid password reset token: %v", err)
			writeError(w, http.StatusBadRequest, "invalid or expired token")
			return
		}

		// Check if token is expired
		if user.PasswordResetExpiry.IsZero() || user.PasswordResetExpiry.Before(time.Now()) {
			logger.Printf("Expired password reset token for user: %s", user.Email)
			writeError(w, http.StatusBadRequest, "token has expired")
			return
		}

		// Hash the new password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			logger.Printf("Error hashing password: %v", err)
			writeError(w, http.StatusInternalServerError, "error updating password")
			return
		}

		// Update user with new password and clear reset token
		err = db.Transaction(func(tx *gorm.DB) error {
			// Clear reset token and expiry, and update password
			updates := map[string]interface{}{
				"password_hash":         string(hashedPassword),
				"password_reset_token":  nil,
				"password_reset_expiry": nil,
				"updated_at":            time.Now(),
			}

			// If user wasn't verified before, mark as verified now
			if !user.IsVerified {
				updates["is_verified"] = true
				logger.Printf("Marking user as verified after password reset: %s", user.Email)
			}

			return tx.Model(&models.DataPrincipal{}).
				Where("id = ?", user.ID).
				Updates(updates).Error
		})

		if err != nil {
			logger.Printf("Error updating user password: %v", err)
			writeError(w, http.StatusInternalServerError, "error updating password")
			return
		}

		logger.Printf("Successfully reset password for user: %s", user.Email)

		// Return success response
		writeJSON(w, http.StatusOK, map[string]string{
			"message": "password has been successfully reset",
		})
	}
}

// UserRefreshHandler handles user token refresh requests
func UserRefreshHandler(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("user_refresh_token")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "missing user refresh token")
			return
		}
		claims, err := auth.ParseDataPrincipalRefreshToken(cookie.Value, publicKey)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid user refresh token")
			return
		}

		// To generate a new token, we need the full user object.
		var user models.DataPrincipal
		userID, err := uuid.Parse(claims.PrincipalID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
			writeError(w, http.StatusUnauthorized, "user not found")
			return
		}

		accessToken, err := auth.GenerateDataPrincipalToken(user, privateKey, cfg.UserTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"token":     accessToken,
			"expiresIn": int64(cfg.UserTokenTTL.Seconds()),
		})
	}
}
