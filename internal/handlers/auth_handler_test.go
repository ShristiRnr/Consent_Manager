package handlers

import (
	"bytes"
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDB initializes an in-memory SQLite database for testing.
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)

	// Automigrate all necessary models
	err = db.AutoMigrate(
		&models.FiduciaryUser{},
		&models.Tenant{},
		&models.Role{},
		&models.Permission{},
	)
	require.NoError(t, err)

	return db
}

func TestImpersonateUserHandler(t *testing.T) {
	db := setupTestDB(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey := &privateKey.PublicKey

	// --- Test Data Setup ---
	tenantID := uuid.New()
	otherTenantID := uuid.New()

	// Permissions
	impersonatePerm := models.Permission{Name: "users:impersonate", Description: "Can impersonate"}
	readUserPerm := models.Permission{Name: "users:read", Description: "Can read users"}
	require.NoError(t, db.Create(&impersonatePerm).Error)
	require.NoError(t, db.Create(&readUserPerm).Error)

	// Roles
	superAdminRole := models.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        "Super Admin",
		Permissions: []*models.Permission{&impersonatePerm, &readUserPerm},
	}
	regularRole := models.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        "Regular User",
		Permissions: []*models.Permission{&readUserPerm}, // No impersonate permission
	}
	require.NoError(t, db.Create(&superAdminRole).Error)
	require.NoError(t, db.Create(&regularRole).Error)

	// Hash a password once
	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Users
	superAdminUser := models.FiduciaryUser{
		ID:           uuid.New(),
		TenantID:     tenantID,
		Email:        "admin@test.com",
		PasswordHash: string(hashedPassword),
		Roles:        []*models.Role{&superAdminRole},
	}
	targetUser := models.FiduciaryUser{
		ID:           uuid.New(),
		TenantID:     tenantID,
		Email:        "target@test.com",
		PasswordHash: string(hashedPassword),
		Roles:        []*models.Role{&regularRole},
	}
	otherTenantUser := models.FiduciaryUser{
		ID:           uuid.New(),
		TenantID:     otherTenantID,
		Email:        "other@test.com",
		PasswordHash: string(hashedPassword),
	}
	require.NoError(t, db.Create(&superAdminUser).Error)
	require.NoError(t, db.Create(&targetUser).Error)
	require.NoError(t, db.Create(&otherTenantUser).Error)

	// Generate JWT for the admin
	adminToken, err := auth.GenerateFiduciaryToken(superAdminUser, privateKey, time.Minute*5)
	require.NoError(t, err)

	// Generate JWT for a user without impersonate permission
	noPermsToken, err := auth.GenerateFiduciaryToken(targetUser, privateKey, time.Minute*5)
	require.NoError(t, err)

	// Create the handler
	cfg := config.Config{AdminTokenTTL: time.Minute * 5}
	handler := ImpersonateUserHandler(db, nil, privateKey, cfg.AdminTokenTTL) // Pass nil for auditService in test

	// --- Test Cases ---

	t.Run("Success - Super Admin impersonates user in same tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fiduciary/users/"+targetUser.ID.String()+"/impersonate", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := httptest.NewRecorder()

		// We need a router to parse the URL variables
		router := mux.NewRouter()
		// The middleware chain is important: first auth, then permission check
		fiduciaryAuth := middlewares.RequireFiduciaryAuth(publicKey)
		permissionCheck := middlewares.RequirePermission("users:impersonate")
		router.Handle("/api/v1/fiduciary/users/{userId}/impersonate", fiduciaryAuth(permissionCheck(handler))).Methods(http.MethodPost)

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		// Verify the response body and the new token
		var resp FiduciaryLoginResponse
		err := json.NewDecoder(rr.Body).Decode(&resp)
		require.NoError(t, err)

		assert.Equal(t, targetUser.ID.String(), resp.FiduciaryID)
		assert.NotEmpty(t, resp.Token)

		// Parse the new impersonation token and verify its claims
		impersonationClaims, err := auth.ParseFiduciaryToken(resp.Token, publicKey)
		require.NoError(t, err)

		assert.Equal(t, targetUser.ID.String(), impersonationClaims.FiduciaryID)
		assert.Equal(t, superAdminUser.ID.String(), impersonationClaims.ImpersonatorID)
		assert.Equal(t, tenantID.String(), impersonationClaims.TenantID)
		assert.True(t, impersonationClaims.Permissions["users:read"])
		assert.False(t, impersonationClaims.Permissions["users:impersonate"]) // Target user does not have this perm
	})

	t.Run("Failure - User without permission tries to impersonate", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fiduciary/users/"+superAdminUser.ID.String()+"/impersonate", nil)
		req.Header.Set("Authorization", "Bearer "+noPermsToken) // Using token of user without permission
		rr := httptest.NewRecorder()

		router := mux.NewRouter()
		fiduciaryAuth := middlewares.RequireFiduciaryAuth(publicKey)
		permissionCheck := middlewares.RequirePermission("users:impersonate")
		router.Handle("/api/v1/fiduciary/users/{userId}/impersonate", fiduciaryAuth(permissionCheck(handler))).Methods(http.MethodPost)

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Contains(t, rr.Body.String(), "insufficient permissions")
	})

	t.Run("Failure - Admin tries to impersonate user in another tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fiduciary/users/"+otherTenantUser.ID.String()+"/impersonate", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := httptest.NewRecorder()

		// We don't need the full middleware chain here since the handler itself should fail
		// But we do need to extract claims and vars
		router := mux.NewRouter()
		router.HandleFunc("/api/v1/fiduciary/users/{userId}/impersonate", func(w http.ResponseWriter, r *http.Request) {
			// Manually inject claims for this test
			claims, _ := auth.ParseFiduciaryToken(adminToken, publicKey)
			ctx := context.WithValue(r.Context(), middlewares.FiduciaryClaimsKey, claims)
			handler(w, r.WithContext(ctx))
		}).Methods(http.MethodPost)

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "User not found in this tenant")
	})

	t.Run("Failure - Invalid target user ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fiduciary/users/not-a-uuid/impersonate", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rr := httptest.NewRecorder()

		router := mux.NewRouter()
		router.HandleFunc("/api/v1/fiduciary/users/{userId}/impersonate", func(w http.ResponseWriter, r *http.Request) {
			claims, _ := auth.ParseFiduciaryToken(adminToken, publicKey)
			ctx := context.WithValue(r.Context(), middlewares.FiduciaryClaimsKey, claims)
			handler(w, r.WithContext(ctx))
		}).Methods(http.MethodPost)

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid user ID format")
	})

	t.Run("Failure - No auth token provided", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fiduciary/users/"+targetUser.ID.String()+"/impersonate", nil)
		// No Authorization header
		rr := httptest.NewRecorder()

		router := mux.NewRouter()
		fiduciaryAuth := middlewares.RequireFiduciaryAuth(publicKey)
		router.Handle("/api/v1/fiduciary/users/{userId}/impersonate", fiduciaryAuth(handler)).Methods(http.MethodPost)

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestFiduciaryLoginHandler(t *testing.T) {
	db := setupTestDB(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// --- Test Data Setup ---
	tenantID := uuid.New()
	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	user := models.FiduciaryUser{
		ID:           uuid.New(),
		TenantID:     tenantID,
		Email:        "login@test.com",
		PasswordHash: string(hashedPassword),
	}
	require.NoError(t, db.Create(&user).Error)

	handler := FiduciaryLoginHandler(db, config.Config{}, privateKey)

	t.Run("Success - Valid credentials", func(t *testing.T) {
		loginReq := LoginRequest{
			Email:    "login@test.com",
			Password: "password123",
		}
		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var resp FiduciaryLoginResponse
		err := json.NewDecoder(rr.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, user.ID.String(), resp.FiduciaryID)
		assert.NotEmpty(t, resp.Token)
	})

	t.Run("Failure - Invalid password", func(t_ *testing.T) {
		loginReq := LoginRequest{
			Email:    "login@test.com",
			Password: "wrongpassword",
		}
		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handler(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "invalid credentials")
	})
}
