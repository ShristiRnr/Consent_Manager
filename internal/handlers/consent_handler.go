package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/encryption"
)

// pubKey is the RSA public key used to verify JWT tokens; replace with your actual key bytes.
var publicKey, _ = auth.LoadPublicKey("public.pem")

type ConsentHandler struct {
	ConsentService *services.ConsentService
}

func NewConsentHandler(cs *services.ConsentService) *ConsentHandler {
	return &ConsentHandler{ConsentService: cs}
}

// RegisterRoutes mounts all handlers on a mux.Router
func (h *ConsentHandler) RegisterRoutes(r *mux.Router, dbConn *gorm.DB) {
	api := r.PathPrefix("/api/v1").Subrouter()

	// Existing routes (kept same)
	api.Handle("/user/consents", middlewares.JWTUserAuthMiddleware(publicKey)(http.HandlerFunc(h.GetUserConsentInTenant))).Methods("GET")
	api.Handle("/user/consentstenantlink",
		middlewares.JWTUserAuthMiddleware(publicKey)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				link, err := h.UserTenantLink(w, r)
				if err != nil {
					writeErr(w, http.StatusBadRequest, err.Error())
					return
				}
				writeJSON(w, http.StatusOK, link)
			}),
		),
	).Methods("GET")
	api.Handle("/tenant/{tenantID}/consents", middlewares.JWTAuthMiddleware(publicKey)(http.HandlerFunc(h.GetConsents))).Methods("GET")
	api.Handle("/user/consents/{consentID}/history", middlewares.JWTUserAuthMiddleware(publicKey)(http.HandlerFunc(h.GetConsentHistory))).Methods("GET")
	api.Handle("/user/consents", middlewares.JWTUserAuthMiddleware(publicKey)(http.HandlerFunc(h.UpdateConsents))).Methods("PUT")
	api.Handle("/public/user/consents", middlewares.JWTUserAuthMiddleware(publicKey)(http.HandlerFunc(h.APIGetUserConsentInTenant))).Methods("GET")
	// api.Handle("/user/consents/withdraw", middlewares.JWTUserAuthMiddleware(publicKey)(http.HandlerFunc(h.WithdrawAllConsents))).Methods("POST")
	api.Handle("/user/consents/withdraw/purpose", middlewares.JWTUserAuthMiddleware(publicKey)(http.HandlerFunc(h.WithdrawConsentByPurpose))).Methods("POST")
	api.Handle("/tenant/{tenantID}/logs",
		middlewares.JWTAuthMiddleware(publicKey)(http.HandlerFunc(h.GetConsentLogs)),
	).Methods("GET")
	api.Handle("/review/{token}", middlewares.JWTUserAuthMiddleware(publicKey)(http.HandlerFunc(h.ReviewConsentSubmission))).Methods("POST")
	api.Handle("/admin/override", middlewares.JWTAuthMiddleware(publicKey)(http.HandlerFunc(h.AdminOverrideConsent))).Methods("POST")
	api.Handle("/admin/tenant/{tenantID}/consents",
		middlewares.JWTAuthMiddleware(publicKey)(
			http.HandlerFunc(h.AdminListTenantConsents),
		),
	).Methods("GET")

	api.Handle("/admin/tenant/{tenantID}/users", middlewares.JWTAuthMiddleware(publicKey)(http.HandlerFunc(h.AdminListTenantUsers))).Methods("GET")

	// In your route setup:
	r.Handle("/api/v1/public/consents",
		middlewares.APIKeyAuthMiddleware(dbConn)(
			http.HandlerFunc(PublicConsentHandler),
		),
	).Methods("POST")

	api.Handle("/admin/tenant/{tenantID}/consents/{userID}",
		middlewares.JWTAuthMiddleware(publicKey)(
			http.HandlerFunc(h.AdminGetUserConsentInTenant),
		),
	).Methods("GET")

	api.Handle("/guardian/consents/approve",
		middlewares.JWTUserAuthMiddleware(publicKey)(http.HandlerFunc(h.GuardianApproveConsent)),
	).Methods("POST")

	api.Handle("/guardian/consents/digilocker/initiate",
		http.HandlerFunc(h.GuardianInitiateDigiLocker),
	).Methods("GET")

	api.Handle("/guardian/consents/digilocker/callback",
		http.HandlerFunc(h.GuardianDigiLockerCallback),
	).Methods("POST")

	// --- New consent link CRUD endpoints (admin only) ---
	api.Handle("/admin/consent-links", middlewares.JWTAuthMiddleware(publicKey)(http.HandlerFunc(h.ListConsentLinks))).Methods("GET")
	api.Handle("/admin/consent-links", middlewares.JWTAuthMiddleware(publicKey)(http.HandlerFunc(h.CreateConsentLink))).Methods("POST")
	api.Handle("/admin/consent-links/{linkID}", middlewares.JWTAuthMiddleware(publicKey)(http.HandlerFunc(h.GetConsentLink))).Methods("GET")
	api.Handle("/admin/consent-links/{linkID}", middlewares.JWTAuthMiddleware(publicKey)(http.HandlerFunc(h.UpdateConsentLink))).Methods("PUT")
	api.Handle("/admin/consent-links/{linkID}", middlewares.JWTAuthMiddleware(publicKey)(http.HandlerFunc(h.DeleteConsentLink))).Methods("DELETE")
}

// Helpers
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

// Handlers

// AdminListTenantUsers etc... (kept unchanged) ------------------------------------------------------------------

func (h *ConsentHandler) AdminListTenantUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := middlewares.GetTenantID(r.Context())
	if len(tenantID) < 8 {
		log.Println("--------------------------------------invalid tenant ID length------------------------------------: ", tenantID)
		writeErr(w, http.StatusInternalServerError, "internal error: invalid tenant id")
		return
	}
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tenantID, ok := r.Context().Value("tenant_id").(string)
	if !ok || tenantID == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized - missing tenant ID")
		return
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil || tid == uuid.Nil {
		writeErr(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}
	consents, err := h.ConsentService.GetAllUserInTenant(r.Context(), tid)
	if err != nil {
		log.Printf("error getting user consents in tenant: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, consents)
}

func (h *ConsentHandler) GetAllUserConsents(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAuthClaims(r)
	log.Println("Getting User Consents")
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized - missing claims")
		log.Println("unauthorized access - missing claims")
		return
	}
	uid, err := uuid.Parse(claims.UserID)
	if err != nil || uid == uuid.Nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized - invalid user ID")
		log.Printf("error parsing user ID: %v", err)
		return
	}

	consents, err := h.ConsentService.GetAllUserConsents(r.Context(), uid)
	if err != nil {
		log.Printf("error getting user consents: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	log.Println("Retrieved consents: ", consents)
	writeJSON(w, http.StatusOK, consents)
}

type userTenant struct {
	ID         string
	UserID     string
	TenantID   string
	TenantName string
}

// UserTenantLink fetch as per userid
func (h *ConsentHandler) UserTenantLink(w http.ResponseWriter, r *http.Request) ([]userTenant, error) {
	// 1. Extract and verify JWT
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("missing authorization header")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid authorization header format")
	}
	token := parts[1]

	// 2. Parse user token
	publicKey, err := auth.LoadPublicKey("public.pem")
	if err != nil {
		log.Printf("failed to load public key: %v", err)
		return nil, err
	}
	parsedToken, err := auth.ParseUserToken(token, publicKey)
	if err != nil {
		return nil, err
	}
	if parsedToken.UserID == "" {
		return nil, errors.New("missing user id - not authenticated")
	}

	// 3. Fetch all tenant links for this user
	var links []models.UserTenantLink
	if err := db.MasterDB.
		Where("user_id = ?", parsedToken.UserID).
		Find(&links).Error; err != nil {
		return nil, err
	}

	// 4. Build response slice
	var result []userTenant
	for _, l := range links {
		var t models.Tenant
		if err := db.MasterDB.
			Where("tenant_id = ?", l.TenantID).
			First(&t).Error; err != nil {
			return nil, err
		}
		result = append(result, userTenant{
			ID:         l.ID.String(),
			UserID:     l.UserID.String(),
			TenantID:   l.TenantID.String(),
			TenantName: t.Name,
		})
	}
	return result, nil
}

func (h *ConsentHandler) GetConsents(w http.ResponseWriter, r *http.Request) {
	tenantID := middlewares.GetTenantID(r.Context())
	if len(tenantID) < 8 {
		log.Println("--------------------------------------invalid tenant ID length------------------------------------: ", tenantID)
		writeErr(w, http.StatusInternalServerError, "internal error: invalid tenant id")
		return
	}
	schema := "tenant_" + tenantID[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		log.Printf("error getting tenant DB: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	consentRepo := repository.NewConsentRepository(tenantDB)
	consentSvc := services.NewConsentService(consentRepo)

	tid, err := uuid.Parse(tenantID)
	if err != nil {
		log.Printf("invalid tenant ID: %v", err)
		writeErr(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}
	purposes, err := consentSvc.GetPurposes(r.Context(), tid)
	if err != nil {
		log.Printf("error getting purposes: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tenantID, ok := r.Context().Value("tenant_id").(string)
	if !ok || tenantID == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized - missing tenant ID")
		return
	}
	writeJSON(w, http.StatusOK, purposes)
}

func (h *ConsentHandler) GetConsentHistory(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAuthClaims(r)
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	uid, err := uuid.Parse(claims.UserID)
	if err != nil || uid == uuid.Nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	consentID := mux.Vars(r)["consentID"]
	if consentID == "" {
		writeErr(w, http.StatusBadRequest, "missing consent ID")
		return
	}

	history, err := h.ConsentService.GetConsentHistory(r.Context(), uid, consentID)
	if err != nil {
		log.Printf("failed to get consent history: %v", err)
		writeErr(w, http.StatusInternalServerError, "error retrieving consent history")
		return
	}
	writeJSON(w, http.StatusOK, history)
}

func (h *ConsentHandler) UpdateConsents(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAuthClaims(r)
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	uid, err := uuid.Parse(claims.UserID)
	if err != nil || uid == uuid.Nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.ConsentService.GetUserByID(r.Context(), uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "user not found")
		return
	}

	var updates []services.ConsentUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	if user.Age < 18 {
		// ---- PARENT/GUARDIAN VERIFICATION ----
		var guardian *models.MasterUser
		if user.GuardianEmail != "" {
			guardian, _ = h.ConsentService.GetUserByEmail(r.Context(), user.GuardianEmail)
		}
		if guardian != nil {
			// Parent/guardian has an account
			err := h.ConsentService.InitiateGuardianDashboardApproval(r.Context(), user, guardian, updates)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "failed to start guardian approval")
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]string{
				"message": "Consent request pending guardian approval from dashboard.",
			})
			return
		}
		// Parent/guardian does not have an account – DigiLocker flow
		err := h.ConsentService.InitiateGuardianDigiLockerVerification(r.Context(), user, updates)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to initiate DigiLocker verification")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{
			"message": "Consent request pending guardian DigiLocker verification.",
		})
		return
	}

	// --- For adults: process as normal ---
	if err := h.ConsentService.UpdateConsents(r.Context(), uid, updates); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to update consents")
		return
	}
	w.WriteHeader(http.StatusOK)
}

// POST /guardian/consents/approve
func (h *ConsentHandler) GuardianApproveConsent(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAuthClaims(r)
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	guardianID, err := uuid.Parse(claims.UserID)
	if err != nil || guardianID == uuid.Nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		PendingConsentID string `json:"pendingConsentId"`
		Approve          bool   `json:"approve"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := h.ConsentService.ProcessGuardianDashboardApproval(r.Context(), guardianID.String(), req.PendingConsentID, req.Approve); err != nil {
		writeErr(w, http.StatusInternalServerError, "approval failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /guardian/consents/digilocker/initiate?pendingConsentId=...
func (h *ConsentHandler) GuardianInitiateDigiLocker(w http.ResponseWriter, r *http.Request) {
	pendingConsentID := r.URL.Query().Get("pendingConsentId")
	if pendingConsentID == "" {
		writeErr(w, http.StatusBadRequest, "missing consent id")
		return
	}
	link, err := h.ConsentService.GenerateDigiLockerLink(r.Context(), pendingConsentID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start DigiLocker flow")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"digilocker_url": link})
}

// POST /guardian/consents/digilocker/callback
func (h *ConsentHandler) GuardianDigiLockerCallback(w http.ResponseWriter, r *http.Request) {
	// DigiLocker posts callback here with verification info
	var req struct {
		PendingConsentID string `json:"pendingConsentId"`
		Verified         bool   `json:"verified"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request payload")
		return
	}
	if err := h.ConsentService.ProcessDigiLockerCallback(r.Context(), req.PendingConsentID, req.Verified); err != nil {
		writeErr(w, http.StatusInternalServerError, "DigiLocker verification failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// withdraw specific consent by purpose
func (h *ConsentHandler) WithdrawConsentByPurpose(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAuthClaims(r)
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		ConsentID string `json:"consentId"`
		Purpose   string `json:"purpose"`
		TenantID  string `json:"tenantId"`
		UserID    string `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid payload")
		return
	}
	log.Printf("Withdrawing consent for user %s, tenant %s, purpose %s, consent ID %s", req.UserID, req.TenantID, req.Purpose, req.ConsentID)
	if err := h.ConsentService.WithdrawConsentByPurpose(r.Context(), req.UserID, req.TenantID, req.Purpose, req.ConsentID); err != nil {
		log.Printf("failed to withdraw consent: %v", err)
		writeErr(w, http.StatusInternalServerError, "unable to withdraw consent")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func GetUserTenantLink(userHeader string) (uuid.UUID, error) {
	// Extract user ID from Authorization header
	parts := strings.SplitN(userHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		log.Println("Invalid Authorization header format")
		return uuid.Nil, errors.New("invalid Authorization header format")
	}
	parsedToken, err := auth.ParseUserToken(parts[1], publicKey)
	if err != nil {
		log.Printf("error parsing user token: %v", err)
		return uuid.Nil, errors.New("invalid or expired token")
	}
	uid, err := uuid.Parse(parsedToken.UserID)
	if err != nil || uid == uuid.Nil {
		log.Printf("error parsing user ID: %v", err)
		return uuid.Nil, errors.New("invalid user ID")
	}
	// Fetch user tenant link
	var link models.UserTenantLink
	if err := db.MasterDB.
		Where("user_id = ?", uid).
		First(&link).Error; err != nil {
		log.Printf("error fetching user tenant link: %v", err)
		return uuid.Nil, errors.New("user tenant link not found")
	}
	return link.TenantID, nil

}

// GET /user/consents
func (h *ConsentHandler) GetUserConsentInTenant(w http.ResponseWriter, r *http.Request) {
	userHeader := r.Header.Get("Authorization")
	if userHeader == "" {
		writeErr(w, http.StatusUnauthorized, "missing Authorization header")
		return
	}
	parts := strings.SplitN(userHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		writeErr(w, http.StatusUnauthorized, "invalid Authorization header format")
		return
	}
	userID := parts[1]
	parsedToken, err := auth.ParseUserToken(userID, publicKey)

	if err != nil {
		log.Printf("error parsing user token: %v", err)
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	uid, err := uuid.Parse(parsedToken.UserID)
	if err != nil || uid == uuid.Nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized - invalid user ID")
		log.Printf("error parsing user ID: %v", err)
		return
	}

	//get tenantid by fetching usertenantlink
	tid, _ := GetUserTenantLink(userHeader)
	schema := "tenant_" + tid.String()[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tenant DB not found")
		return
	}
	consent, err := h.ConsentService.GetUserConsentInTenant(r.Context(), tenantDB, tid, uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not fetch consent")
		return
	}
	writeJSON(w, http.StatusOK, consent)
}

// APIGetUserConsentInTenant
func (h *ConsentHandler) APIGetUserConsentInTenant(w http.ResponseWriter, r *http.Request) {
	apikey := r.Header.Get("X-API-Key")
	if apikey == "" {
		writeErr(w, http.StatusUnauthorized, "missing API key")
		return
	}
	tenantID, err := resolveTenantIDFromAPIKey(apikey)
	if err != nil || tenantID == uuid.Nil {
		writeErr(w, http.StatusUnauthorized, "invalid or revoked API key")
		return
	}
	schema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		log.Printf("Failed to get tenant DB: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Parse userID from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeErr(w, http.StatusUnauthorized, "missing Authorization header")
		return
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		writeErr(w, http.StatusUnauthorized, "invalid Authorization header format")
		return
	}
	token := parts[1]
	parsedToken, err := auth.ParseUserToken(token, publicKey)
	if err != nil {
		log.Printf("error parsing user token: %v", err)
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	uid, err := uuid.Parse(parsedToken.UserID)
	if err != nil || uid == uuid.Nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized - invalid user ID")
		log.Printf("error parsing user ID: %v", err)
		return
	}
	consent, err := h.ConsentService.GetUserConsentInTenant(r.Context(), tenantDB, tenantID, uid)
	if err != nil {
		log.Printf("error getting user consent in tenant: %v", err)
		writeErr(w, http.StatusInternalServerError, "could not fetch consent")
		return
	}
	writeJSON(w, http.StatusOK, consent)
}

func (h *ConsentHandler) GetConsentLogs(w http.ResponseWriter, r *http.Request) {
	tenantID := middlewares.GetTenantID(r.Context())
	if len(tenantID) < 8 {
		log.Println("--------------------------------------invalid tenant ID length------------------------------------: ", tenantID)
		writeErr(w, http.StatusInternalServerError, "internal error: invalid tenant id")
		return
	}
	schema := "tenant_" + tenantID[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		log.Printf("error getting tenant DB: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	consentRepo := repository.NewConsentRepository(tenantDB)
	consentSvc := services.NewConsentService(consentRepo)
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tenantID, ok := r.Context().Value("tenant_id").(string)
	if !ok || tenantID == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized - missing tenant ID")
		return
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil || tid == uuid.Nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	logsData, err := consentSvc.GetConsentLogs(r.Context(), tid)
	if err != nil {
		log.Printf("failed to retrieve logs: %v", err)
		writeErr(w, http.StatusInternalServerError, "failed to retrieve logs")
		return
	}
	writeJSON(w, http.StatusOK, logsData)
}

// --------- Request DTO ---------
type PublicConsentRequest struct {
	ExternalUserID string          `json:"external_user_id"`
	Purposes       []PurposeInput  `json:"purposes"`
	PolicySnapshot json.RawMessage `json:"policy_snapshot,omitempty"` // optional
	GeoRegion      string          `json:"geo_region,omitempty"`
	Jurisdiction   string          `json:"jurisdiction,omitempty"`
	LinkID         string          `json:"link_id,omitempty"` // NEW: optional link id to increment counters
}
type PurposeInput struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"`        // optional, can be filled later
	Description  string   `json:"description,omitempty"` // optional, can be filled later
	Vendors      []string `json:"vendors,omitempty"`     // optional, can be filled later
	IsThirdParty bool     `json:"is_third_party,omitempty"`
	Status       bool     `json:"status"`
	Version      string   `json:"version,omitempty"`
}

// --------- Response DTO ---------
type PublicConsentResponse struct {
	Status string `json:"status"`
}

type PurposeConsentStatus struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name,omitempty"`        // optional, can be filled later
	Description  string    `json:"description,omitempty"` // optional, can be filled later
	IsThirdParty bool      `json:"is_third_party,omitempty"`
	Vendors      []string  `json:"vendors,omitempty"` // optional, can be filled later
	Status       bool      `json:"status"`
	Version      string    `json:"version,omitempty"`
}

// Helper for secure tenant lookup
func resolveTenantIDFromAPIKey(apiKey string) (uuid.UUID, error) {
	lookupHash, err := encryption.DeterministicEncrypt(apiKey)
	if err != nil {
		return uuid.Nil, err
	}
	var key models.APIKey
	if err := db.MasterDB.Where("hashed_key = ? AND revoked = false", lookupHash).First(&key).Error; err != nil {
		return uuid.Nil, err
	}
	//verify the key matches the raw API key
	if key.HashedKey != lookupHash {
		log.Printf("API key mismatch: %s != %s", key.HashedKey, lookupHash)
		return uuid.Nil, nil
	}

	return key.TenantID, nil
}

func PublicConsentHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Securely get tenant ID from API key
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		http.Error(w, "missing API key", http.StatusUnauthorized)
		return
	}
	tenantID, err := resolveTenantIDFromAPIKey(apiKey)
	if err != nil || tenantID == uuid.Nil {
		http.Error(w, "invalid or revoked API key", http.StatusUnauthorized)
		return
	}

	// 2. Parse and validate request
	var req PublicConsentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.ExternalUserID == "" || len(req.Purposes) == 0 {
		http.Error(w, "missing external_user_id or purposes", http.StatusBadRequest)
		return
	}

	// 3. Load correct tenant DB
	schema := "tenant_" + tenantID.String()[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		log.Printf("Failed to get tenant DB: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 3.5 Check if master_user exists
	var masterUser models.MasterUser
	err = db.MasterDB.Where("email = ?", req.ExternalUserID).First(&masterUser).Error
	if err != nil {
		// If not found, inform the user that they need to register
		http.Error(w, "user not registered", http.StatusNotFound)
		return
	} else {
		// Update last seen time
		db.MasterDB.Model(&masterUser).Update("last_seen", time.Now())
	}

	// 3.6 Associate master user with tenant
	var tenantUser models.UserTenantLink
	err = db.MasterDB.Where("user_id = ? AND tenant_id = ?", masterUser.UserID, tenantID).First(&tenantUser).Error
	if err != nil {
		// If not found, create a new tenant user link
		tenantUser = models.UserTenantLink{
			ID:             uuid.New(),
			UserID:         masterUser.UserID,
			TenantID:       tenantID,
			TenantName:     schema,
			FirstGrantedAt: time.Now(),
			LastUpdatedAt:  time.Now(),
		}
		if err := db.MasterDB.Create(&tenantUser).Error; err != nil {
			http.Error(w, "could not create tenant user link", http.StatusInternalServerError)
			return
		}
	} else {
		// Update last seen time for tenant user
		db.MasterDB.Model(&tenantUser).Update("last_seen", time.Now())
	}

	// 5. Prepare consent status JSON
	var statuses []PurposeConsentStatus
	for _, p := range req.Purposes {
		pid, err := uuid.Parse(p.ID)
		if err != nil {
			http.Error(w, "invalid purpose id: "+p.ID, http.StatusBadRequest)
			return
		}
		statuses = append(statuses, PurposeConsentStatus{
			ID:           pid,
			Name:         p.Name,
			Description:  p.Description,
			IsThirdParty: p.IsThirdParty,
			Vendors:      p.Vendors,
			Status:       p.Status,
			Version:      p.Version,
		})
	}
	purposesJSON, err := json.Marshal(statuses)
	if err != nil {
		http.Error(w, "could not marshal purposes", http.StatusInternalServerError)
		return
	}

	//convert purposesJSON to dto.ConsentPurposes
	var consentPurposes []dto.ConsentPurpose
	if err := json.Unmarshal(purposesJSON, &consentPurposes); err != nil {
		log.Printf("error unmarshalling purposes: %v", err)
		http.Error(w, "could not unmarshal purposes", http.StatusInternalServerError)
		return
	}

	//[]dto.ConsentPurpose to dto.ConsentPurposes
	consentPurposesDTO := dto.ConsentPurposes{
		Purposes: make([]dto.ConsentPurpose, len(consentPurposes)),
	}
	for i, p := range consentPurposes {
		consentPurposesDTO.Purposes[i] = dto.ConsentPurpose{
			ID:          p.ID,
			Name:        p.Name,
			Description: p.Description,
			Status:      p.Status,
		}
	}

	policySnap := req.PolicySnapshot
	if len(policySnap) == 0 {
		purposeBytes, err := json.Marshal(req.Purposes)
		if err != nil {
			http.Error(w, "could not marshal purposes for policy snapshot", http.StatusInternalServerError)
			return
		}
		policySnap = []byte(`{"purposes":` + string(purposeBytes) + `}`)
	}

	// 7. Create or update consent record
	var consent models.Consent
	now := time.Now()
	err = tenantDB.Where("user_id = ? AND tenant_id = ?", tenantUser.UserID, tenantID).First(&consent).Error
	if err != nil {
		consent = models.Consent{
			ID:             uuid.New(),
			UserID:         tenantUser.UserID,
			TenantID:       tenantID,
			Purposes:       consentPurposesDTO,
			PolicySnapshot: datatypes.JSON(policySnap),
			GeoRegion:      req.GeoRegion,
			Jurisdiction:   req.Jurisdiction,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := tenantDB.Create(&consent).Error; err != nil {
			http.Error(w, "could not create consent", http.StatusInternalServerError)
			return
		}
	} else {
		consent.Purposes = consentPurposesDTO
		consent.PolicySnapshot = datatypes.JSON(policySnap)
		consent.GeoRegion = req.GeoRegion
		consent.Jurisdiction = req.Jurisdiction
		consent.UpdatedAt = now
		if err := tenantDB.Save(&consent).Error; err != nil {
			http.Error(w, "could not update consent", http.StatusInternalServerError)
			return
		}
	}

	// 8. Insert consent history
	history := models.ConsentHistory{
		ID:             uuid.New(),
		ConsentID:      consent.ID,
		UserID:         tenantUser.UserID,
		TenantID:       tenantID,
		Action:         "public_consent_update",
		Purposes:       datatypes.JSON(purposesJSON),
		ChangedBy:      "public_api",
		PolicySnapshot: datatypes.JSON(policySnap),
		Timestamp:      now,
	}
	_ = tenantDB.Create(&history)

	// ---- NEW: if request contains LinkID, increment submission_count in master consent_links table ----
	if req.LinkID != "" {
		if lid, err := uuid.Parse(req.LinkID); err == nil {
			consentRepo := repository.NewConsentRepository(db.MasterDB)
			linkSvc := services.NewConsentLinkService(consentRepo)
			if err := linkSvc.IncrementSubmission(lid); err != nil {
				// Non-fatal; log warning
				log.Printf("warning: couldn't increment consent link submission for %s: %v", lid, err)
			}
		} else {
			log.Printf("invalid link id provided in request body: %s", req.LinkID)
		}
	}

	// 11. Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PublicConsentResponse{Status: "ok"})
}

func (h *ConsentHandler) ReviewConsentSubmission(w http.ResponseWriter, r *http.Request) {
	// Authenticate user
	claims := middlewares.GetAuthClaims(r)
	if claims == nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusFound)
		return
	}
	userID := claims.Subject

	// Parse form or JSON
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid form submission")
		return
	}

	// Purposes from form: "purposes[]" checkboxes or JSON string (adapt as per your form)
	var submitted []PurposeInput
	for _, id := range r.Form["purpose_id"] {
		status := r.Form.Get("status_"+id) == "on"
		version := r.Form.Get("version_" + id)
		submitted = append(submitted, PurposeInput{ID: id, Status: status, Version: version})
	}

	callback := r.FormValue("callback")
	clientID := r.FormValue("client_id")

	// Optionally: revalidate clientID/callback if needed here
	if clientID == "" || callback == "" {
		writeErr(w, http.StatusBadRequest, "Missing client_id or callback")
		return
	}

	// Update the user's consents using ConsentService
	uid, _ := uuid.Parse(userID)
	// Map submitted form data to the service request type
	var updates []services.ConsentUpdateRequest
	for _, p := range submitted {
		updates = append(updates, services.ConsentUpdateRequest{
			Purposes: []dto.Purpose{
				{
					Consented: p.Status,
					Version:   p.Version,
				},
			},
			TenantID: uuid.MustParse(middlewares.GetTenantID(r.Context())),
		})
	}
	if err := h.ConsentService.UpdateConsents(r.Context(), uid, updates); err != nil {
		writeErr(w, http.StatusInternalServerError, "Failed to update consents")
		return
	}

	// Redirect back to the callback with success status (or with error if needed)
	cbUrl, _ := url.Parse(callback)
	q := cbUrl.Query()
	q.Set("status", "success")
	cbUrl.RawQuery = q.Encode()
	http.Redirect(w, r, cbUrl.String(), http.StatusSeeOther)
}

// GET /api/v1/admin/tenant/{tenantID}/consents
func (h *ConsentHandler) AdminListTenantConsents(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tenantID := mux.Vars(r)["tenantID"]
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tenantID")
		return
	}
	// Get correct tenant DB
	schema := "tenant_" + tid.String()[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tenant DB not found")
		return
	}
	consents, err := h.ConsentService.GetAllConsentsByTenant(r.Context(), tenantDB, tid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not fetch consents")
		return
	}
	writeJSON(w, http.StatusOK, consents)
}

// GET /api/v1/admin/tenant/{tenantID}/consents/{userID}
func (h *ConsentHandler) AdminGetUserConsentInTenant(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	vars := mux.Vars(r)
	tenantID, userID := vars["tenantID"], vars["userID"]
	tid, err := uuid.Parse(tenantID)
	uid, err2 := uuid.Parse(userID)
	if err != nil || err2 != nil {
		writeErr(w, http.StatusBadRequest, "invalid IDs")
		return
	}
	schema := "tenant_" + tid.String()[:8]
	tenantDB, err := db.GetTenantDB(schema)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tenant DB not found")
		return
	}
	consent, err := h.ConsentService.GetUserConsentInTenant(r.Context(), tenantDB, tid, uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not fetch consent")
		return
	}
	writeJSON(w, http.StatusOK, consent)
}

func (h *ConsentHandler) AdminOverrideConsent(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeErr(w, http.StatusUnauthorized, "missing Authorization header")
		return
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		writeErr(w, http.StatusUnauthorized, "invalid Authorization header format")
		return
	}
	token := parts[1]
	parsedToken, err := auth.ParseAdminToken(token, publicKey)
	if err != nil {
		log.Printf("error parsing admin token: %v", err)
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	tidStr := parsedToken.TenantID
	if tidStr == "" {
		writeErr(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}
	tid, err := uuid.Parse(tidStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tenant ID format")
		return
	}
	var ov services.AdminConsentOverride
	if err := json.NewDecoder(r.Body).Decode(&ov); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid input")
		return
	}

	if err := h.ConsentService.AdminOverrideConsent(r.Context(), tid, ov); err != nil {
		log.Printf("error overriding consent: %v", err)
		writeErr(w, http.StatusInternalServerError, "override failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ----------------- New handlers for ConsentLink CRUD -----------------

// CreateConsentLink creates a consent link (admin)
func (h *ConsentHandler) CreateConsentLink(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		Link     string          `json:"link"`
		Name     string          `json:"name,omitempty"`
		TenantID string          `json:"tenantId"`
		Metadata json.RawMessage `json:"metadata,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid payload")
		return
	}
	tid, err := uuid.Parse(req.TenantID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	link := &models.ConsentLink{
		Link:     req.Link,
		Name:     req.Name,
		TenantID: tid,
		Metadata: []byte(req.Metadata),
	}
	consentRepo := repository.NewConsentRepository(db.MasterDB)
	linkSvc := services.NewConsentLinkService(consentRepo)
	if err := linkSvc.CreateLink(link); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create consent link")
		return
	}
	writeJSON(w, http.StatusCreated, link)
}

// GetConsentLink returns a consent link by ID
func (h *ConsentHandler) GetConsentLink(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	idStr := mux.Vars(r)["linkID"]
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid link id")
		return
	}
	consentRepo := repository.NewConsentRepository(db.MasterDB)
	linkSvc := services.NewConsentLinkService(consentRepo)
	link, err := linkSvc.GetLinkByID(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if link == nil {
		writeErr(w, http.StatusNotFound, "link not found")
		return
	}
	writeJSON(w, http.StatusOK, link)
}

// ListConsentLinks lists consent links by tenant
func (h *ConsentHandler) ListConsentLinks(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tidStr := r.URL.Query().Get("tenantId")
	if tidStr == "" {
		tidStr = middlewares.GetTenantID(r.Context())
	}
	tid, err := uuid.Parse(tidStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid tenant id")
		return
	}
	consentRepo := repository.NewConsentRepository(db.MasterDB)
	linkSvc := services.NewConsentLinkService(consentRepo)
	links, err := linkSvc.ListLinksByTenant(tid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, links)
}

// UpdateConsentLink updates a consent link
func (h *ConsentHandler) UpdateConsentLink(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	idStr := mux.Vars(r)["linkID"]
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid link id")
		return
	}
	var req struct {
		Link     string          `json:"link,omitempty"`
		Name     string          `json:"name,omitempty"`
		Metadata json.RawMessage `json:"metadata,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid payload")
		return
	}
	consentRepo := repository.NewConsentRepository(db.MasterDB)
	linkSvc := services.NewConsentLinkService(consentRepo)
	link, err := linkSvc.GetLinkByID(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if link == nil {
		writeErr(w, http.StatusNotFound, "link not found")
		return
	}
	if req.Link != "" {
		link.Link = req.Link
	}
	if req.Name != "" {
		link.Name = req.Name
	}
	if req.Metadata != nil {
		link.Metadata = []byte(req.Metadata)
	}
	if err := linkSvc.UpdateLink(link); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not update link")
		return
	}
	writeJSON(w, http.StatusOK, link)
}

// DeleteConsentLink deletes a consent link
func (h *ConsentHandler) DeleteConsentLink(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetAdminAuthClaims(r.Context())
	if claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	idStr := mux.Vars(r)["linkID"]
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid link id")
		return
	}
	consentRepo := repository.NewConsentRepository(db.MasterDB)
	linkSvc := services.NewConsentLinkService(consentRepo)
	if err := linkSvc.DeleteLink(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not delete link")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
