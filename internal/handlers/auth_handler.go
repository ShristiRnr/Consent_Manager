package handlers

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/auth"
	contextKey "consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/log"
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
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
	Token       string `json:"token"`
	FiduciaryID string `json:"fiduciaryId"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	TenantID    string `json:"tenantId"`
	ExpiresIn   int64  `json:"expiresIn"`
	Role        string `json:"role"`
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

		accessToken, err := auth.GenerateFiduciaryToken(fiduciary, privateKey, cfg.AdminTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		refreshToken, err := auth.GenerateFiduciaryRefreshToken(fiduciary, privateKey, cfg.AdminRefreshTokenTTL)
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

		resp := FiduciaryLoginResponse{
			Token:       accessToken,
			FiduciaryID: fiduciary.ID.String(),
			Email:       fiduciary.Email,
			Phone:       fiduciary.Phone,
			TenantID:    fiduciary.TenantID.String(),
			ExpiresIn:   int64(cfg.AdminTokenTTL.Seconds()),
			Role:        fiduciary.Role,
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// -------------------------
// Superadmin Creates User
// -------------------------

type CreateUserRequest struct {
	Email              string `json:"email"`
	Phone              string `json:"phone"`
	Password           string `json:"password"`
	FirstName          string `json:"firstName"`
	LastName           string `json:"lastName"`
	Age                int    `json:"age"`
	GuardianEmail      string `json:"guardianEmail"`
	Location           string `json:"location"`
	Role               string `json:"role"`
	CanManageConsent   bool   `json:"canManageConsent"`
	CanManageGrievance bool   `json:"canManageGrievance"`
	CanManagePurposes  bool   `json:"canManagePurposes"`
	CanManageAuditLogs bool   `json:"canManageAuditLogs"`
}

func FiduciaryCreateUserHandler(db *gorm.DB, auditService *services.AuditService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextKey.FiduciaryClaimsKey).(*auth.FiduciaryClaims)
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

		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		newUser := models.FiduciaryUser{
			ID:                 uuid.New(),
			TenantID:           uuid.MustParse(claims.TenantID),
			Email:              req.Email,
			Phone:              req.Phone,
			PasswordHash:       string(hash),
			Name:               req.FirstName + " " + req.LastName,
			Role:               req.Role,
			CanManageConsent:   req.CanManageConsent,
			CanManageGrievance: req.CanManageGrievance,
			CanManagePurposes:  req.CanManagePurposes,
			CanManageAuditLogs: req.CanManageAuditLogs,
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
				"role":  newUser.Role,
			})
		}

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"message": "user created successfully",
			"userId":  newUser.ID,
		})
	}
}

func UserMeHandler(db *gorm.DB, auditService *services.AuditService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextKey.UserClaimsKey).(*auth.DataPrincipalClaims)
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
		claims, ok := r.Context().Value(contextKey.UserClaimsKey).(*auth.DataPrincipalClaims)
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
			Name:     "refresh_token",
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

func FiduciaryMeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fiduciary, err := GetFiduciaryData(db.MasterDB, r.Context())
		if err != nil {
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
