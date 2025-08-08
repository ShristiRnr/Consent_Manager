package handlers

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/auth"
	contextKey "consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/pkg/log"
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token               string   `json:"token"`
	UserID              string   `json:"userId"`
	Email               string   `json:"email"`
	Phone               string   `json:"phone"`
	Tenants             []string `json:"tenants,omitempty"`
	Role                string   `json:"role"`
	CanManageConsent    bool     `json:"canManageConsent,omitempty"`
	CanManageGrievance  bool     `json:"canManageGrievance,omitempty"`
	CanManagePurposes   bool     `json:"canManagePurposes,omitempty"`
	CanManageAuditLogs  bool     `json:"canManageAuditLogs,omitempty"`
	ExpiresIn           int64    `json:"expiresIn"`
}

type AdminLoginResponse struct {
	Token     string `json:"token"`
	AdminID   string `json:"adminId"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	TenantID  string `json:"tenantId"`
	ExpiresIn int64  `json:"expiresIn"`
	Role      string `json:"role"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

// ===== Common Utility =====
func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}


// ===== USER AUTH HANDLERS =====

func UserLoginHandler(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey) http.HandlerFunc {
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

		var user models.MasterUser
		if err := db.Preload("Tenants").Where("email = ?", req.Email).First(&user).Error; err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		tenantIDs := make([]string, len(user.Tenants))
		for i, t := range user.Tenants {
			tenantIDs[i] = t.TenantID.String()
		}

		accessToken, err := auth.GenerateUserToken(user, tenantIDs, privateKey, cfg.UserTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		refreshToken, err := auth.GenerateUserRefreshToken(user, tenantIDs, privateKey, cfg.UserRefreshTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(cfg.UserRefreshTokenTTL.Seconds()),
		})

		resp := LoginResponse{
			Token:              accessToken,
			UserID:             user.UserID.String(),
			Email:              user.Email,
			Phone:              user.Phone,
			Tenants:            tenantIDs,
			Role:               user.Role,
			CanManageConsent:   user.CanManageConsent,
			CanManageGrievance: user.CanManageGrievance,
			CanManagePurposes:  user.CanManagePurposes,
			CanManageAuditLogs: user.CanManageAuditLogs,
			ExpiresIn:          int64(cfg.UserTokenTTL.Seconds()),
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func UserRefreshHandler(cfg config.Config, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("refresh_token")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "missing refresh token")
			return
		}
		claims, err := auth.ParseUserRefreshToken(cookie.Value, publicKey)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid refresh token")
			return
		}
		accessToken, err := auth.GenerateUserToken(claims.User, claims.Tenants, privateKey, cfg.UserTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "token generation failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"token":     accessToken,
			"expiresIn": int64(cfg.UserTokenTTL.Seconds()),
		})
	}
}

// ===== ADMIN AUTH HANDLERS =====

func AdminLoginHandler(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey) http.HandlerFunc {
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

		var admin models.AdminUser
		if err := db.Where("LOWER(email) = ?", strings.ToLower(req.Email)).First(&admin).Error; err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		accessToken, err := auth.GenerateAdminToken(admin.AdminID.String(), admin.TenantID.String(), admin.Role, privateKey, cfg.AdminTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		refreshToken, err := auth.GenerateAdminRefreshToken(admin.AdminID.String(), admin.TenantID.String(), admin.Role, privateKey, cfg.AdminRefreshTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "admin_refresh_token",
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(cfg.AdminRefreshTokenTTL.Seconds()),
		})

		resp := AdminLoginResponse{
			Token:     accessToken,
			AdminID:   admin.AdminID.String(),
			Email:     admin.Email,
			Phone:     admin.Phone,
			TenantID:  admin.TenantID.String(),
			ExpiresIn: int64(cfg.AdminTokenTTL.Seconds()),
			Role:      admin.Role,
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

func AdminCreateUserHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		if req.Email == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "email and password required")
			return
		}

		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		newUser := models.MasterUser{
			UserID:              uuid.New(),
			Email:               req.Email,
			Phone:               req.Phone,
			Password:            string(hash),
			FirstName:           req.FirstName,
			LastName:            req.LastName,
			Age:                 req.Age,
			GuardianEmail:       req.GuardianEmail,
			Location:            req.Location,
			Role:                req.Role,
			CanManageConsent:    req.CanManageConsent,
			CanManageGrievance:  req.CanManageGrievance,
			CanManagePurposes:   req.CanManagePurposes,
			CanManageAuditLogs:  req.CanManageAuditLogs,
			CreatedAt:           time.Now(),
		}

		if err := db.Create(&newUser).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create user")
			return
		}

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"message": "user created successfully",
			"userId":  newUser.UserID,
		})
	}
}

func UpdateUserHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextKey.UserClaimsKey).(*auth.UserClaims)
		if !ok || claims == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var user models.MasterUser
		if err := db.Where("user_id = ?", claims.UserID).First(&user).Error; err != nil {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}

		var updateData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		if email, ok := updateData["email"].(string); ok {
			user.Email = email
		}
		if phone, ok := updateData["phone"].(string); ok {
			user.Phone = phone
		}
		if firstName, ok := updateData["firstName"].(string); ok {
			user.FirstName = firstName
		}
		if lastName, ok := updateData["lastName"].(string); ok {
			user.LastName = lastName
		}
		if location, ok := updateData["location"].(string); ok {
			user.Location = location
		}
		if ageFloat, ok := updateData["age"].(float64); ok {
			user.Age = int(ageFloat)
		}
		if guardianEmail, ok := updateData["guardianEmail"].(string); ok {
			user.GuardianEmail = guardianEmail
		}

		if err := db.Save(&user).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update user")
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message": "user updated successfully",
			"user":    user,
		})
	}
}

func UserMeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextKey.UserClaimsKey).(*auth.UserClaims)
		if !ok || claims == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		user, err := middlewares.GetUserData(db.MasterDB, r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to fetch user data")
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"user_id": claims.UserID,
			"user": map[string]interface{}{
				"id":        user.UserID.String(),
				"firstName": user.FirstName,
				"lastName":  user.LastName,
				"age":       user.Age,
				"guardian":  user.GuardianEmail,
				"location":  user.Location,
				"email":     user.Email,
				"phone":     user.Phone,
				"tenants":   user.Tenants,
				"createdAt": user.CreatedAt,
			},
			"email":              claims.Email,
			"phone":              claims.Phone,
			"tenants":            claims.Tenants,
			"role":               claims.User.Role,               // moved inside User
			"canManageConsent":   claims.User.CanManageConsent,   // moved inside User
			"canManageGrievance": claims.User.CanManageGrievance, // moved inside User
			"canManagePurposes":  claims.User.CanManagePurposes,  // moved inside User
			"canManageAuditLogs": claims.User.CanManageAuditLogs, // moved inside User
			"exp":                claims.ExpiresAt,
			"iat":                claims.IssuedAt,
		})
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

func UserForgotPasswordHandler(db *gorm.DB, emailSender func(to, token string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ForgotPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		var user models.MasterUser
		if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
			writeJSON(w, http.StatusOK, map[string]string{"message": "if user exists, email sent"})
			return
		}

		resetToken := uuid.New().String()
		user.PasswordResetToken = resetToken
		user.PasswordResetExpiry = time.Now().Add(30 * time.Minute)
		db.Save(&user)

		_ = emailSender(user.Email, resetToken)
		writeJSON(w, http.StatusOK, map[string]string{"message": "if user exists, email sent"})
	}
}

func UserResetPasswordHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		var user models.MasterUser
		if err := db.Where("password_reset_token = ?", req.Token).First(&user).Error; err != nil {
			writeError(w, http.StatusBadRequest, "invalid or expired token")
			return
		}
		if user.PasswordResetExpiry.Before(time.Now()) {
			writeError(w, http.StatusBadRequest, "token expired")
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to set password")
			return
		}

		user.Password = string(hash)
		user.PasswordResetToken = ""
		user.PasswordResetExpiry = time.Time{}
		db.Save(&user)

		writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
	}
}

func AdminMeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextKey.AdminClaimsKey).(*auth.AdminClaims)
		if !ok || claims == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		admin, err := GetAdminData(db.MasterDB, r.Context())
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				writeError(w, http.StatusNotFound, "admin not found")
				return
			}
			log.Logger.Error().Err(err).Msg("failed to fetch admin data")
			writeError(w, http.StatusInternalServerError, "failed to fetch admin data")
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"admin_id":   claims.AdminID,
			"tenant_id":  claims.TenantID,
			"email":      admin.Email,
			"phone":      admin.Phone,
			"name":       admin.Name,
			"created_at": admin.CreatedAt,
			"role":       claims.Role,
			"exp":        claims.ExpiresAt,
			"iat":        claims.IssuedAt,
		})
	}
}

func GetAdminData(db *gorm.DB, ctx context.Context) (*models.AdminUser, error) {
	claims, ok := ctx.Value(contextKey.AdminClaimsKey).(*auth.AdminClaims)
	if !ok || claims == nil {
		return nil, http.ErrNoCookie
	}

	var admin models.AdminUser
	if err := db.Where("admin_id = ?", claims.AdminID).First(&admin).Error; err != nil {
		return nil, err
	}
	return &admin, nil
}

func GetAdminById() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var admin models.AdminUser
		if err := db.MasterDB.Where("admin_id = ?", r.Header.Get("admin_id")).First(&admin).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				writeError(w, http.StatusNotFound, "admin not found")
				return
			}
			log.Logger.Error().Err(err).Msg("failed to fetch admin data")
			writeError(w, http.StatusInternalServerError, "failed to fetch admin data")
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"admin_id":   admin.AdminID,
			"tenant_id":  admin.TenantID,
			"email":      admin.Email,
			"phone":      admin.Phone,
			"name":       admin.Name,
			"created_at": admin.CreatedAt,
			"role":       admin.Role,
		})
	}
}

func AdminRefreshHandler(cfg config.Config, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("admin_refresh_token")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "missing admin refresh token")
			return
		}
		claims, err := auth.ParseAdminRefreshToken(cookie.Value, publicKey)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid admin refresh token")
			return
		}

		accessToken, err := auth.GenerateAdminToken(claims.AdminID, claims.TenantID, claims.Role, privateKey, cfg.AdminTokenTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "token generation failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"token":     accessToken,
			"expiresIn": int64(cfg.AdminTokenTTL.Seconds()),
		})
	}
}

func AdminLogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_refresh_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message": "admin logged out",
		})
	}
}

func AdminForgotPasswordHandler(db *gorm.DB, emailSender func(to, token string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ForgotPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		var admin models.AdminUser
		if err := db.Where("email = ?", req.Email).First(&admin).Error; err != nil {
			writeJSON(w, http.StatusOK, map[string]string{"message": "if admin exists, email sent"})
			return
		}

		resetToken := uuid.New().String()
		admin.PasswordResetToken = resetToken
		admin.PasswordResetExpiry = time.Now().Add(30 * time.Minute)
		db.Save(&admin)

		_ = emailSender(admin.Email, resetToken)
		writeJSON(w, http.StatusOK, map[string]string{"message": "if admin exists, email sent"})
	}
}

func AdminResetPasswordHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}

		var admin models.AdminUser
		if err := db.Where("password_reset_token = ?", req.Token).First(&admin).Error; err != nil {
			writeError(w, http.StatusBadRequest, "invalid or expired token")
			return
		}
		if admin.PasswordResetExpiry.Before(time.Now()) {
			writeError(w, http.StatusBadRequest, "token expired")
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to set password")
			return
		}

		admin.PasswordHash = string(hash)
		admin.PasswordResetToken = ""
		admin.PasswordResetExpiry = time.Time{}
		db.Save(&admin)

		writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
	}
}
