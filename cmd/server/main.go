package main

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/handlers"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/realtime"
	"consultrnr/consent-manager/internal/repository"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/encryption"
	"consultrnr/consent-manager/pkg/jwtlink"
	"consultrnr/consent-manager/pkg/log"
	"encoding/json"
	"net/http"
	"strings"

	muxHandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/mvrilo/go-redoc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ===== Superadmin-only middleware =====
func requireAdminRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(contextkeys.AdminClaimsKey).(*auth.AdminClaims)
			if !ok || claims == nil {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
				return
			}
			for _, role := range roles {
				if strings.EqualFold(claims.Role, role) {
					next.ServeHTTP(w, r)
					return
				}
			}
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: insufficient role"})

		})
	}
}

func main() {
	// Load config and init systems
	cfg := config.LoadConfig()
	log.InitLogger()
	jwtlink.Init(cfg.JWTSecret)
	if err := encryption.InitEncryption(); err != nil {
		log.Logger.Fatal().Err(err).Msg("encryption init failed")
	}
	log.Logger.Info().Msg("encryption ready")

	// API Docs
	doc := &redoc.Redoc{
		Title:       "Consent Manager API",
		Description: "Manage user consents, grievances & notifications",
		SpecFile:    "./cmd/server/docs/swagger.json",
		SpecPath:    "/swagger/doc.json",
		DocsPath:    "/docs",
	}

	// DB init
	db.InitDB(cfg)

	// Router & CORS
	r := mux.NewRouter()
	cors := muxHandlers.CORS(
		muxHandlers.AllowedOrigins([]string{"http://localhost:5173"}),
		muxHandlers.AllowedMethods([]string{
			http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions,
		}),
		muxHandlers.AllowedHeaders([]string{
			"Content-Type", "Authorization", "X-API-Key", "X-Tenant-ID",
		}),
		muxHandlers.AllowCredentials(),
	)

	// Core repos/services/hub
	consentRepo := repository.NewConsentRepository(db.MasterDB)
	consentSvc := services.NewConsentService(consentRepo)
	notifRepo := repository.NewNotificationRepo(db.MasterDB)
	hub := realtime.NewHub()

	// Health & docs
	r.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("OK"))
	}).Methods("GET")
	r.HandleFunc(doc.SpecPath, func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, doc.SpecFile)
	}).Methods("GET")
	r.Handle(doc.DocsPath, doc.Handler()).Methods("GET")

	// JWT keys
	privateKey, err := auth.LoadPrivateKey("private.pem")
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to load private key")
	}
	publicKey, err := auth.LoadPublicKey("public.pem")
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to load public key")
	}

	// Middlewares
	userAuth := middlewares.RequireUserAuth(publicKey)
	adminAuth := middlewares.RequireAdminAuth(publicKey)
	apiKeyAuth := middlewares.APIKeyAuthMiddleware(db.MasterDB)
	requirePerm := middlewares.RequirePermission

	// ==== AUTH: USER ====
	r.Handle("/api/v1/auth/user/login", handlers.UserLoginHandler(db.MasterDB, cfg, privateKey)).Methods("POST")
	r.Handle("/api/v1/auth/user/me", userAuth(handlers.UserMeHandler())).Methods("GET")
	r.Handle("/api/v1/auth/user/refresh", handlers.UserRefreshHandler(cfg, privateKey, publicKey)).Methods("POST")
	r.Handle("/api/v1/auth/user/logout", userAuth(handlers.UserLogoutHandler())).Methods("POST")
	r.Handle("/api/v1/user/profile", userAuth(handlers.UpdateUserHandler(db.MasterDB))).Methods("PUT")
	r.Handle("/api/v1/auth/user/reset-password", handlers.UserResetPasswordHandler(db.MasterDB)).Methods("POST")

	// ==== AUTH: ADMIN ====
	r.Handle("/api/v1/auth/admin/login", handlers.AdminLoginHandler(db.MasterDB, cfg, privateKey)).Methods("POST")
	r.Handle("/api/v1/auth/admin/me", adminAuth(handlers.AdminMeHandler())).Methods("GET")
	r.Handle("/api/v1/auth/admin/refresh", adminAuth(handlers.AdminRefreshHandler(cfg, privateKey, publicKey))).Methods("POST")
	r.Handle("/api/v1/auth/admin/logout", adminAuth(handlers.AdminLogoutHandler())).Methods("POST")
	r.Handle("/api/v1/auth/admin/reset-password", handlers.AdminResetPasswordHandler(db.MasterDB)).Methods("POST")
	r.Handle("/api/v1/auth/admin/identify", adminAuth(handlers.GetAdminById())).Methods("POST")

	// ==== SIGNUP ====
	signupHandler := handlers.NewSignupHandler(db.MasterDB, cfg)
	r.Handle("/api/v1/admin/users",
		adminAuth(requireAdminRole("superadmin")(http.HandlerFunc(handlers.AdminCreateUserHandler(db.MasterDB))))).
		Methods("POST")
	r.HandleFunc("/api/v1/auth/user/signup", signupHandler.SignupUser).Methods("POST")
	r.HandleFunc("/api/v1/auth/admin/signup", signupHandler.SignupOrganization).Methods("POST")

	// ==== TEST: USERMANAGEMENT PERMISSION ====
	r.Handle("/api/v1/admin/usermanagement-test",
		adminAuth(requirePerm("usermanagement")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := r.Context().Value(contextkeys.AdminClaimsKey)
			role := "unknown"
			if ac, ok := claims.(*auth.AdminClaims); ok {
				role = ac.Role
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Access granted to usermanagement module",
				"module":  "usermanagement",
				"role":    role,
			})
		}))),
	).Methods("GET")

	// ==== CONSENT ====
	consentHandler := handlers.NewConsentHandler(consentSvc)
	consentHandler.RegisterRoutes(r, db.MasterDB)

	// ==== PARTNER API ====
	partnerR := r.PathPrefix("/api/v1/partner").Subrouter()
	partnerR.HandleFunc("/consents", func(w http.ResponseWriter, r *http.Request) {
		apiKeyAuth(http.HandlerFunc(handlers.PartnerGetConsentsHandler)).ServeHTTP(w, r)
	}).Methods("GET")

	// ==== USER DSR ====
	DSRhandlers := handlers.NewDataRequestHandler(db.MasterDB)
	r.Handle("/api/v1/user/requests", userAuth(requirePerm("consent")(http.HandlerFunc(DSRhandlers.ListUserRequests)))).Methods("GET")
	r.Handle("/api/v1/user/requests", userAuth(requirePerm("consent")(http.HandlerFunc(DSRhandlers.CreateUserRequest)))).Methods("POST")
	r.Handle("/api/v1/user/requests/{id}", userAuth(requirePerm("consent")(http.HandlerFunc(DSRhandlers.GetRequestDetails)))).Methods("GET")

	// ==== ADMIN DSR ====
	r.Handle("/api/v1/admin/requests", adminAuth(requirePerm("consent")(http.HandlerFunc(DSRhandlers.ListAdminRequests)))).Methods("GET")
	r.Handle("/api/v1/admin/requests/{id}", adminAuth(requirePerm("consent")(http.HandlerFunc(DSRhandlers.GetAdminRequestDetails)))).Methods("GET")
	r.Handle("/api/v1/admin/requests/{id}/approve", adminAuth(requirePerm("consent")(http.HandlerFunc(DSRhandlers.ApproveRequest)))).Methods("POST")
	r.Handle("/api/v1/admin/requests/{id}/reject", adminAuth(requirePerm("consent")(http.HandlerFunc(DSRhandlers.RejectRequest)))).Methods("POST")

	// ==== PURPOSES ====
	r.Handle("/api/v1/user/purposes", adminAuth(requirePerm("purposes")(http.HandlerFunc(handlers.ListPurposesHandler())))).Methods("GET")
	r.Handle("/api/v1/user/purposes/{id}", userAuth(requirePerm("purposes")(http.HandlerFunc(handlers.UserGetPurposeHandler())))).Methods("GET")
	r.Handle("/api/v1/user/purposes/tenant/{tenantID}", userAuth(requirePerm("purposes")(http.HandlerFunc(handlers.UserGetPurposeByTenant())))).Methods("GET")
	r.Handle("/api/v1/admin/purposes", adminAuth(requirePerm("purposes")(http.HandlerFunc(handlers.CreatePurposeHandler())))).Methods("POST")
	r.Handle("/api/v1/admin/purposes/{id}", adminAuth(requirePerm("purposes")(http.HandlerFunc(handlers.UpdatePurposeHandler())))).Methods("PUT")
	r.Handle("/api/v1/admin/purposes", adminAuth(requirePerm("purposes")(http.HandlerFunc(handlers.DeletePurposeHandler())))).Methods("DELETE")

	purposeHandler := handlers.NewPurposeHandler(db.Clusters["tenant"])
	r.Handle("/api/v1/purposes/{id}/activate", adminAuth(requirePerm("purposes")(http.HandlerFunc(purposeHandler.ToggleActive)))).Methods("POST")
	r.Handle("/api/v1/public/purposes", apiKeyAuth(http.HandlerFunc(handlers.GetPurposes))).Methods("GET")

	// ==== API KEYS ====
	r.Handle("/api/v1/admin/api-keys", adminAuth(requirePerm("usermanagement")(http.HandlerFunc(handlers.CreateAPIKeyHandler(db.MasterDB, publicKey))))).Methods("POST")
	r.Handle("/api/v1/admin/api-keys", adminAuth(requirePerm("usermanagement")(http.HandlerFunc(handlers.ListAPIKeysHandler(db.MasterDB, publicKey))))).Methods("GET")
	r.Handle("/api/v1/admin/api-keys/revoke", adminAuth(requirePerm("usermanagement")(http.HandlerFunc(handlers.RevokeAPIKeyHandler(db.MasterDB, publicKey))))).Methods("PUT")

	// ==== TENANT SETTINGS ====
	r.Handle("/api/v1/admin/tenant/settings", adminAuth(requirePerm("usermanagement")(http.HandlerFunc(handlers.UpdateTenantSettingsHandler(db.MasterDB))))).Methods("PUT")

	// ==== AUDIT LOGS ====
	adminGR := r.PathPrefix("/api/v1/admin").Subrouter()
	adminGR.Use(adminAuth)
	adminGR.Use(requirePerm("auditlogs"))
	adminGR.Use(handlers.TenantContextMiddleware)
	adminGR.HandleFunc("/audit/logs", handlers.GetTenantAuditLogsHandler()).Methods("GET")

	// ==== GRIEVANCES ====
	grievHandler := handlers.NewGrievanceHandler(notifRepo, hub)
	r.Handle("/api/v1/dashboard/grievances", userAuth(requirePerm("grievance")(http.HandlerFunc(grievHandler.Create)))).Methods("POST")
	r.Handle("/api/v1/dashboard/grievances", userAuth(requirePerm("grievance")(http.HandlerFunc(grievHandler.ListForUser)))).Methods("GET")

	adminGR.Use(adminAuth)
	adminGR.Handle("/grievances", requirePerm("grievance")(http.HandlerFunc(grievHandler.List))).Methods("GET")
	adminGR.Handle("/grievances/{id}", requirePerm("grievance")(http.HandlerFunc(grievHandler.Update))).Methods("PUT")

	// ===== Grievance Comments =====
	r.Handle("/api/v1/dashboard/grievances/{id}/comments", userAuth(requirePerm("grievance")(http.HandlerFunc(grievHandler.AddComment)))).Methods("POST")
	r.Handle("/api/v1/dashboard/grievances/{id}/comments", userAuth(requirePerm("grievance")(http.HandlerFunc(grievHandler.GetComments)))).Methods("GET")
	r.Handle("/api/v1/dashboard/grievances/comments/{commentID}", userAuth(requirePerm("grievance")(http.HandlerFunc(grievHandler.DeleteComment)))).Methods("DELETE")

	adminGR.Handle("/grievances/{id}/comments", requirePerm("grievance")(http.HandlerFunc(grievHandler.AddComment))).Methods("POST")
	adminGR.Handle("/grievances/{id}/comments", requirePerm("grievance")(http.HandlerFunc(grievHandler.GetComments))).Methods("GET")
	adminGR.Handle("/grievances/comments/{commentID}", requirePerm("grievance")(http.HandlerFunc(grievHandler.DeleteComment))).Methods("DELETE")
	
	// ==== VENDOR ====
	vendorRepo := repository.NewVendorRepository(db.MasterDB)
	vendorService := services.NewVendorService(vendorRepo)
	vendorHandler := handlers.NewVendorHandler(vendorService)

	// Public or all-authenticated users can list/get vendor details
	r.Handle("/api/v1/vendors", userAuth(http.HandlerFunc(vendorHandler.ListVendors))).Methods("GET")
	r.Handle("/api/v1/vendors/{id}", userAuth(http.HandlerFunc(vendorHandler.GetVendorByID))).Methods("GET")

	// Admin & Superadmin can create/update/delete
	r.Handle("/api/v1/admin/vendors", adminAuth(requireAdminRole("admin", "superadmin")(http.HandlerFunc(vendorHandler.CreateVendor)))).Methods("POST")
	r.Handle("/api/v1/admin/vendors/{id}", adminAuth(requireAdminRole("admin", "superadmin")(http.HandlerFunc(vendorHandler.UpdateVendor)))).Methods("PUT")
	r.Handle("/api/v1/admin/vendors/{id}", adminAuth(requireAdminRole("admin", "superadmin")(http.HandlerFunc(vendorHandler.DeleteVendor)))).Methods("DELETE")

	// ==== REVIEW TOKEN & METRICS ====
	r.HandleFunc("/api/v1/review", handlers.ReviewTokenHandler(db.MasterDB, publicKey)).Methods("GET")
	r.Handle("/metrics", promhttp.Handler())

	// ==== START SERVER ====
	handler := cors(r)
	log.Logger.Info().Msgf("Server starting on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, handler); err != nil {
		log.Logger.Fatal().Err(err).Msg("server failed")
	}
}
