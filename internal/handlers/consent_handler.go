package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/log"
)

// pubKey is the RSA public key used to verify JWT tokens; replace with your actual key bytes.
var publicKey, _ = auth.LoadPublicKey("public.pem")

type ConsentHandler struct {
	ConsentService *services.ConsentService
	AuditService   *services.AuditService
}

func NewConsentHandler(cs *services.ConsentService, as *services.AuditService) *ConsentHandler {
	return &ConsentHandler{ConsentService: cs, AuditService: as}
}

// RegisterRoutes mounts all handlers on a mux.Router
func (h *ConsentHandler) RegisterRoutes(r *mux.Router, dbConn *gorm.DB) {
	api := r.PathPrefix("/api/v1").Subrouter()

	// Existing routes (kept same)
	api.Handle("/user/consents", middlewares.JWTDataPrincipalAuthMiddleware(publicKey)(http.HandlerFunc(h.GetUserConsentInTenant))).Methods("GET")
	api.Handle("/user/consentstenantlink",
		middlewares.JWTDataPrincipalAuthMiddleware(publicKey)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				link, err := h.UserTenantLink(w, r)
				if err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeJSON(w, http.StatusOK, link)
			}),
		),
	).Methods("GET")
	api.Handle("/tenant/{tenantID}/consents", middlewares.JWTFiduciaryAuthMiddleware(publicKey)(http.HandlerFunc(h.GetConsents))).Methods("GET")
	api.Handle("/user/consents/{consentID}/history", middlewares.JWTDataPrincipalAuthMiddleware(publicKey)(http.HandlerFunc(h.GetConsentHistory))).Methods("GET")
	api.Handle("/user/consents", middlewares.JWTDataPrincipalAuthMiddleware(publicKey)(http.HandlerFunc(h.UpdateConsents))).Methods("PUT")
	api.Handle("/public/user/consents", middlewares.JWTDataPrincipalAuthMiddleware(publicKey)(http.HandlerFunc(h.APIGetUserConsentInTenant))).Methods("GET")
	// api.Handle("/user/consents/withdraw", middlewares.JWTDataPrincipalAuthMiddleware(publicKey)(http.HandlerFunc(h.WithdrawAllConsents))).Methods("POST")
	api.Handle("/user/consents/withdraw/purpose", middlewares.JWTDataPrincipalAuthMiddleware(publicKey)(http.HandlerFunc(h.WithdrawConsentByPurpose))).Methods("POST")
	api.Handle("/tenant/{tenantID}/logs",
		middlewares.JWTFiduciaryAuthMiddleware(publicKey)(http.HandlerFunc(h.GetConsentLogs)),
	).Methods("GET")
	api.Handle("/admin/override", middlewares.JWTFiduciaryAuthMiddleware(publicKey)(http.HandlerFunc(h.AdminOverrideConsent))).Methods("POST")
	api.Handle("/admin/tenant/{tenantID}/consents",
		middlewares.JWTFiduciaryAuthMiddleware(publicKey)(
			http.HandlerFunc(h.AdminListTenantConsents),
		),
	).Methods("GET")

	api.Handle("/admin/tenant/{tenantID}/users", middlewares.JWTFiduciaryAuthMiddleware(publicKey)(http.HandlerFunc(h.AdminListTenantUsers))).Methods("GET")

	// In your route setup:
	// r.Handle("/api/v1/public/consents",
	// 	middlewares.APIKeyAuthMiddleware(dbConn)(
	// 		http.HandlerFunc(PublicConsentHandler),
	// 	),
	// ).Methods("POST")

	api.Handle("/admin/tenant/{tenantID}/consents/{userID}",
		middlewares.JWTFiduciaryAuthMiddleware(publicKey)(
			http.HandlerFunc(h.AdminGetUserConsentInTenant),
		),
	).Methods("GET")

	api.Handle("/guardian/consents/approve",
		middlewares.JWTDataPrincipalAuthMiddleware(publicKey)(http.HandlerFunc(h.GuardianApproveConsent)),
	).Methods("POST")

	api.Handle("/guardian/consents/digilocker/initiate",
		http.HandlerFunc(h.GuardianInitiateDigiLocker),
	).Methods("GET")

	api.Handle("/guardian/consents/digilocker/callback",
		http.HandlerFunc(h.GuardianDigiLockerCallback),
	).Methods("POST")

	// --- New consent link CRUD endpoints (admin only) ---
	api.Handle("/admin/consent-links", middlewares.JWTFiduciaryAuthMiddleware(publicKey)(http.HandlerFunc(h.ListConsentLinks))).Methods("GET")
	api.Handle("/admin/consent-links", middlewares.JWTFiduciaryAuthMiddleware(publicKey)(http.HandlerFunc(h.CreateConsentLink))).Methods("POST")
	api.Handle("/admin/consent-links/{linkID}", middlewares.JWTFiduciaryAuthMiddleware(publicKey)(http.HandlerFunc(h.GetConsentLink))).Methods("GET")
	api.Handle("/admin/consent-links/{linkID}", middlewares.JWTFiduciaryAuthMiddleware(publicKey)(http.HandlerFunc(h.UpdateConsentLink))).Methods("PUT")
	api.Handle("/admin/consent-links/{linkID}", middlewares.JWTFiduciaryAuthMiddleware(publicKey)(http.HandlerFunc(h.DeleteConsentLink))).Methods("DELETE")
}

func (h *ConsentHandler) AdminListTenantUsers(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := mux.Vars(r)["tenantID"]
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	consents, err := h.ConsentService.GetAllUserInTenant(r.Context(), tenantID)
	if err != nil {
		log.Logger.Error().Msgf("error getting user consents in tenant: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, consents)
}

func (h *ConsentHandler) GetAllUserConsents(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized - missing claims")
		log.Logger.Error().Msg("unauthorized access - missing claims")
		return
	}
	uid, err := uuid.Parse(claims.ID)
	if err != nil || uid == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized - invalid user ID")
		log.Logger.Error().Msgf("error parsing user ID: %v", err)
		return
	}

	consents, err := h.ConsentService.GetAllUserConsents(r.Context(), uid)
	if err != nil {
		log.Logger.Error().Msgf("Error getting consent: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
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
	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		return nil, errors.New("user access required")
	}

	var user models.DataPrincipal
	if err := db.MasterDB.Where("id = ?", claims.ID).First(&user).Error; err != nil {
		return nil, errors.New("user not found")
	}

	var tenant models.Tenant
	if err := db.MasterDB.Where("id = ?", user.TenantID).First(&tenant).Error; err != nil {
		return nil, errors.New("tenant not found")
	}

	userTenants := []userTenant{
		{
			ID:         tenant.TenantID.String(), // This might need adjustment based on what ID is expected.
			UserID:     user.ID.String(),
			TenantID:   tenant.TenantID.String(),
			TenantName: tenant.Name,
		},
	}

	return userTenants, nil
}

func (h *ConsentHandler) GetConsents(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := mux.Vars(r)["tenantID"]
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}

	consents, err := h.ConsentService.FetchConsentsByTenant(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not fetch consents")
		return
	}
	writeJSON(w, http.StatusOK, consents)
}

func (h *ConsentHandler) GetConsentHistory(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	consentIDStr := mux.Vars(r)["consentID"]
	consentID, err := uuid.Parse(consentIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid consent id")
		return
	}

	uid, _ := uuid.Parse(claims.ID)
	history, err := h.ConsentService.GetConsentHistory(r.Context(), uid, consentID.String())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get history")
		return
	}

	writeJSON(w, http.StatusOK, history)
}

func (h *ConsentHandler) UpdateConsents(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var updates []services.ConsentUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	var consentUpdates []services.ConsentUpdateRequest
	for _, u := range updates {
		consentUpdates = append(consentUpdates, services.ConsentUpdateRequest{
			TenantID: u.TenantID,
			Purposes: u.Purposes,
		})
	}
	uid, _ := uuid.Parse(claims.ID)
	if err := h.ConsentService.UpdateConsents(r.Context(), uid, consentUpdates); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update consents")
		return
	}

	// Audit log
	for _, update := range updates {
		for _, purpose := range update.Purposes {
			consentedStr := "false"
			if purpose.Consented {
				consentedStr = "true"
			}
			go h.AuditService.Create(r.Context(), uid, update.TenantID, purpose.ID, "consent_updated", consentedStr, claims.ID, r.RemoteAddr, "", "", map[string]interface{}{"purpose_id": purpose.ID, "consented": purpose.Consented})
		}
	}
	w.WriteHeader(http.StatusOK)
}

// POST /guardian/consents/approve
func (h *ConsentHandler) GuardianApproveConsent(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	guardianID, err := uuid.Parse(claims.ID)
	if err != nil || guardianID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		PendingConsentID string `json:"pending_consent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	pendingConsentID, err := uuid.Parse(req.PendingConsentID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pending consent id")
		return
	}

	if err := h.ConsentService.ProcessGuardianDashboardApproval(r.Context(), guardianID.String(), pendingConsentID.String(), true); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to approve consent")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// GET /guardian/consents/digilocker/initiate?pendingConsentId=...
func (h *ConsentHandler) GuardianInitiateDigiLocker(w http.ResponseWriter, r *http.Request) {
	pendingConsentID := r.URL.Query().Get("pendingConsentId")
	if pendingConsentID == "" {
		writeError(w, http.StatusBadRequest, "missing consent id")
		return
	}
	link, err := h.ConsentService.GenerateDigiLockerLink(r.Context(), pendingConsentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start DigiLocker flow")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"digilocker_url": link})
}

// POST /guardian/consents/digilocker/callback
func (h *ConsentHandler) GuardianDigiLockerCallback(w http.ResponseWriter, r *http.Request) {
	// DigiLocker posts callback here with verification info
	var req struct {
		PendingConsentID string `json:"pending_consent_id"`
		Verified         bool   `json:"verified"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}
	if err := h.ConsentService.ProcessDigiLockerCallback(r.Context(), req.PendingConsentID, req.Verified); err != nil {
		writeError(w, http.StatusInternalServerError, "DigiLocker verification failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// withdraw specific consent by purpose
func (h *ConsentHandler) WithdrawConsentByPurpose(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		UserID   string `json:"user_id"`
		TenantID string `json:"tenant_id"`
		Purpose  string `json:"purpose"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// This handler seems to be missing consentID, which is required by the service.
	// For now, we'll pass a nil UUID, but this needs to be fixed.
	if err := h.ConsentService.WithdrawConsentByPurpose(r.Context(), req.UserID, req.TenantID, req.Purpose, uuid.Nil.String()); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to withdraw consent")
		return
	}

	uid, _ := uuid.Parse(req.UserID)
	tid, _ := uuid.Parse(req.TenantID)
	pid, _ := uuid.Parse(req.Purpose)
	go h.AuditService.Create(r.Context(), uid, tid, pid, "consent_withdrawn", "", claims.ID, r.RemoteAddr, "", "", map[string]interface{}{"purpose_id": req.Purpose})

	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *ConsentHandler) GetUserConsentInTenant(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "user access required")
		return
	}

	uid, _ := uuid.Parse(claims.ID)
	tid, _ := uuid.Parse(claims.TenantID)
	consents, err := h.ConsentService.GetUserConsentInTenant(r.Context(), db.MasterDB, tid, uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get consents")
		return
	}

	writeJSON(w, http.StatusOK, consents)
}

func (h *ConsentHandler) APIGetUserConsentInTenant(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		writeError(w, http.StatusUnauthorized, "missing api key")
		return
	}

	tenantID, err := resolveTenantIDFromAPIKey(apiKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid api key")
		return
	}

	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "user access required")
		return
	}

	uid, err := uuid.Parse(claims.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	consents, err := h.ConsentService.GetUserConsentInTenant(r.Context(), db.MasterDB, tenantID, uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get consents for tenant")
		return
	}

	writeJSON(w, http.StatusOK, consents)
}

func (h *ConsentHandler) GetConsentLogs(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "Fiduciary claims not found")
		return
	}

	tenantID := mux.Vars(r)["tenantID"]
	if claims.TenantID != tenantID {
		writeError(w, http.StatusForbidden, "You are not authorized to access this tenant's logs")
		return
	}

	logs, err := h.AuditService.GetConsentAuditLogs(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get logs")
		return
	}

	writeJSON(w, http.StatusOK, logs)
}

func (h *ConsentHandler) AdminOverrideConsent(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*auth.FiduciaryClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "fiduciary access required")
		return
	}

	var overrideReq services.AdminConsentOverride
	if err := json.NewDecoder(r.Body).Decode(&overrideReq); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Call the service method to override the consent
	if err := h.ConsentService.AdminOverrideConsent(r.Context(), overrideReq); err != nil {
		log.Logger.Error().Err(err).Msg("Failed to override consent")
		writeError(w, http.StatusInternalServerError, "failed to override consent")
		return
	}

	log.Logger.Info().Msgf("Admin user %s (tenant: %s) successfully overrode consent for user %s", claims.ID, claims.TenantID, overrideReq.UID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "consent override successful"})
}

// TODO: Move to a more appropriate place, maybe a helper package
func resolveTenantIDFromAPIKey(apiKey string) (uuid.UUID, error) {
	return db.GetTenantIDFromAPIKey(apiKey)
}

func (h *ConsentHandler) AdminListTenantConsents(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := mux.Vars(r)["tenantID"]
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}

	consents, err := h.ConsentService.FetchConsentsByTenant(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get consents")
		return
	}

	writeJSON(w, http.StatusOK, consents)
}

func (h *ConsentHandler) AdminGetUserConsentInTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantIDStr := vars["tenantID"]
	userIDStr := vars["userID"]

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID")
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	consents, err := h.ConsentService.GetUserConsentInTenant(r.Context(), db.MasterDB, tenantID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get consents")
		return
	}

	writeJSON(w, http.StatusOK, consents)
}

func (h *ConsentHandler) ListConsentLinks(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant id")
		return
	}

	linkSvc := services.NewConsentLinkService(h.ConsentService.Repo())
	links, err := linkSvc.ListLinksByTenant(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list consent links")
		return
	}
	writeJSON(w, http.StatusOK, links)
}

func (h *ConsentHandler) CreateConsentLink(w http.ResponseWriter, r *http.Request) {
	var link models.ConsentLink
	if err := json.NewDecoder(r.Body).Decode(&link); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	linkSvc := services.NewConsentLinkService(h.ConsentService.Repo())
	if err := linkSvc.CreateLink(&link); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create consent link")
		return
	}
	writeJSON(w, http.StatusCreated, link)
}

func (h *ConsentHandler) GetConsentLink(w http.ResponseWriter, r *http.Request) {
	linkIDStr := mux.Vars(r)["linkID"]
	linkID, err := uuid.Parse(linkIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid link id")
		return
	}

	linkSvc := services.NewConsentLinkService(h.ConsentService.Repo())
	link, err := linkSvc.GetLinkByID(linkID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get consent link")
		return
	}
	writeJSON(w, http.StatusOK, link)
}

func (h *ConsentHandler) UpdateConsentLink(w http.ResponseWriter, r *http.Request) {
	linkIDStr := mux.Vars(r)["linkID"]
	linkID, err := uuid.Parse(linkIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid link id")
		return
	}

	var link models.ConsentLink
	if err := json.NewDecoder(r.Body).Decode(&link); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}
	link.ID = linkID

	linkSvc := services.NewConsentLinkService(h.ConsentService.Repo())
	if err := linkSvc.UpdateLink(&link); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update consent link")
		return
	}
	writeJSON(w, http.StatusOK, link)
}

func (h *ConsentHandler) DeleteConsentLink(w http.ResponseWriter, r *http.Request) {
	linkIDStr := mux.Vars(r)["linkID"]
	linkID, err := uuid.Parse(linkIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid link id")
		return
	}

	linkSvc := services.NewConsentLinkService(h.ConsentService.Repo())
	if err := linkSvc.DeleteLink(linkID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete consent link")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
