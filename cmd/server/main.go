package main

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/handlers"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/realtime"
	"consultrnr/consent-manager/internal/repository"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/encryption"
	"consultrnr/consent-manager/pkg/jwtlink"
	"consultrnr/consent-manager/pkg/log"
	"fmt"
	"net/http"

	muxHandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/mvrilo/go-redoc"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"

	"gorm.io/gorm"
)

func seedPermissions(db *gorm.DB) {
	permissions := []models.Permission{
		{Name: "users:create", Description: "Can create new fiduciary users"},
		{Name: "users:read", Description: "Can view fiduciary users"},
		{Name: "users:update", Description: "Can update fiduciary users"},
		{Name: "users:delete", Description: "Can delete fiduciary users"},
		{Name: "users:impersonate", Description: "Can impersonate another user within the tenant"},
		{Name: "roles:manage", Description: "Can create, update, and delete roles"},
		{Name: "organizations:manage", Description: "Can manage organization entities"},
		{Name: "consents:read", Description: "Can view consent records"},
		{Name: "consents:update", Description: "Can update consent records"},
		{Name: "purposes:manage", Description: "Can manage consent purposes"},
		{Name: "consent-forms:manage", Description: "Can manage consent forms"},
		{Name: "grievances:read", Description: "Can view grievances"},
		{Name: "grievances:respond", Description: "Can respond to grievances"},
		{Name: "audit-logs:read", Description: "Can view audit logs"},
		{Name: "api-keys:manage", Description: "Can manage API keys"},
		{Name: "breaches:manage", Description: "Can manage breach notifications"},
		{Name: "dpas:manage", Description: "Can manage Data Processing Agreements"},
	}

	for _, p := range permissions {
		db.FirstOrCreate(&p, models.Permission{Name: p.Name})
	}
	log.Logger.Info().Msg("Permissions seeded successfully.")
}

func seedDatabase(gormDB *gorm.DB) {
	// Check if a default tenant exists, and if not, create one.
	var tenantCount int64
	gormDB.Model(&models.Tenant{}).Count(&tenantCount)
	if tenantCount == 0 {
		testTenantID := uuid.New()
		defaultTenant := models.Tenant{
			TenantID: testTenantID,
			Name:     "Default Test Tenant",
		}
		if err := gormDB.Create(&defaultTenant).Error; err != nil {
			log.Logger.Fatal().Err(err).Msg("Failed to seed database with default tenant")
		}
		log.Logger.Info().Str("tenant_id", testTenantID.String()).Msg("Created default test tenant")
	} else {
		log.Logger.Info().Msg("Database already seeded.")
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
	doc := redoc.Redoc{
		Title:       "Consent Manager API",
		Description: "Manage user consents, grievances & notifications",
		SpecFile:    "./cmd/server/docs/swagger.json",
		SpecPath:    "/swagger.json",
		DocsPath:    "/docs",
	}

	// DB init
	db.InitDB(cfg)
	seedPermissions(db.MasterDB)
	seedDatabase(db.MasterDB)

	// Router & CORS
	r := mux.NewRouter()
	cors := muxHandlers.CORS(
		muxHandlers.AllowedOrigins([]string{cfg.FrontendBaseURL}),
		muxHandlers.AllowedMethods([]string{
			http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions,
		}),
		muxHandlers.AllowedHeaders([]string{
			"Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin",
		}),
		muxHandlers.AllowCredentials(),
	)

	// Health & docs
	r.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("OK"))
	}).Methods("GET")
	r.Handle(doc.DocsPath, doc.Handler())
	r.Handle(doc.SpecPath, http.FileServer(http.Dir("./cmd/server/docs/")))

	// Core repos/services/hub
	consentRepo := repository.NewConsentRepository(db.MasterDB)
	auditRepo := repository.NewAuditRepo(db.MasterDB)
	auditService := services.NewAuditService(auditRepo)
	consentSvc := services.NewConsentService(consentRepo, auditService)
	notifRepo := repository.NewNotificationRepo(db.MasterDB)
	hub := realtime.NewHub()
	consentFormRepo := repository.NewConsentFormRepository(db.MasterDB)
	consentFormSvc := services.NewConsentFormService(consentFormRepo)
	userConsentRepo := repository.NewUserConsentRepository(db.MasterDB)
	userConsentSvc := services.NewUserConsentService(userConsentRepo, consentFormRepo)
	webhookSvc := services.NewWebhookService(db.MasterDB)

	// Breach Notification Service
	breachNotificationRepo := repository.NewBreachNotificationRepository(db.MasterDB)
	breachNotificationSvc := services.NewBreachNotificationService(breachNotificationRepo)

	// DSR Service
	dsrRepo := repository.NewDSRRepository(db.MasterDB, nil) // TenantDB is fetched dynamically
	dsrService := services.NewDSRService(dsrRepo)

	notificationPreferencesRepo := repository.NewNotificationPreferencesRepo(db.MasterDB)

	// Fiduciary Service
	fiduciaryRepo := repository.NewFiduciaryRepository(db.MasterDB)
	fiduciaryService := services.NewFiduciaryService(fiduciaryRepo)

	// New Services
	emailService := services.NewEmailService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass)
	notificationPreferencesService := services.NewNotificationPreferencesService(notificationPreferencesRepo)
	notificationService := services.NewNotificationService(notifRepo, notificationPreferencesRepo, emailService, hub, fiduciaryService)

	// JWT keys
	privateKey, err := auth.LoadPrivateKey("private.pem")
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to load private key")
	}
	publicKey, err := auth.LoadPublicKey("public.pem")
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to load public key")
	}

	// Auth middleware
	dataPrincipalAuth := middlewares.RequireDataPrincipalAuth(publicKey)
	fiduciaryAuth := middlewares.RequireFiduciaryAuth(publicKey)
	apiKeyAuth := middlewares.APIKeyAuthMiddleware(db.MasterDB)
	requirePerm := middlewares.RequirePermission

	// Wrapper for sending password reset email
	sendResetEmail := func(to, token string) error {
		resetLink := fmt.Sprintf("%s/reset-password?token=%s", cfg.BaseURL, token)
		body := fmt.Sprintf("Please click on the following link to reset your password: <a href=\"%s\">Reset Password</a>", resetLink)
		return emailService.Send(to, "Password Reset Request", body)
	}

	// ==== AUTH: USER ====
	r.Handle("/api/v1/auth/user/login", handlers.UserLoginHandler(db.MasterDB, cfg, privateKey)).Methods("POST")
	r.Handle("/api/v1/auth/user/forgot-password", dataPrincipalAuth(handlers.UserForgotPasswordHandler(db.MasterDB, sendResetEmail))).Methods("POST")
	r.Handle("/api/v1/auth/user/reset-password", dataPrincipalAuth(handlers.UserResetPasswordHandler(db.MasterDB))).Methods("POST")
	r.Handle("/api/v1/auth/user/refresh", dataPrincipalAuth(handlers.UserRefreshHandler(db.MasterDB, cfg, privateKey, publicKey))).Methods("POST")
	r.Handle("/api/v1/auth/user/logout", dataPrincipalAuth(handlers.UserLogoutHandler())).Methods("POST")
	r.Handle("/api/v1/user/profile", dataPrincipalAuth(handlers.UpdateUserHandler(db.MasterDB, auditService))).Methods("PUT")
	r.Handle("/api/v1/auth/user/me", dataPrincipalAuth(handlers.UserMeHandler(db.MasterDB, auditService))).Methods("GET")

	// ==== FIDUCIARY AUTH ====
	authRouter := r.PathPrefix("/api/v1/auth/fiduciary").Subrouter()
	authRouter.HandleFunc("/login", handlers.FiduciaryLoginHandler(db.MasterDB, cfg, privateKey)).Methods("POST")
	authRouter.HandleFunc("/refresh", handlers.FiduciaryRefreshHandler(db.MasterDB, cfg, privateKey, publicKey)).Methods("POST")
	authRouter.Handle("/me", fiduciaryAuth(handlers.FiduciaryMeHandler(db.MasterDB))).Methods("GET")
	authRouter.HandleFunc("/forgot-password", handlers.FiduciaryForgotPasswordHandler(db.MasterDB, sendResetEmail)).Methods("POST")
	authRouter.HandleFunc("/reset-password", handlers.FiduciaryResetPasswordHandler(db.MasterDB)).Methods("POST")
	authRouter.HandleFunc("/logout", handlers.FiduciaryLogoutHandler()).Methods("POST")

	// ==== ORGANIZATION MANAGEMENT ====
	orgRepo := repository.NewOrganizationRepository(db.MasterDB)
	orgService := services.NewOrganizationService(orgRepo)
	orgHandler := handlers.NewOrganizationHandler(orgService, orgRepo)

	// Public or all-authenticated users can list/get organization details
	r.Handle("/public/api/v1/organizations", http.HandlerFunc(orgHandler.ListOrganizations)).Methods("GET")
	r.Handle("/public/api/v1/organizations/{id}", http.HandlerFunc(orgHandler.GetOrganizationByID)).Methods("GET")
	r.Handle("/public/api/v1/organizations/name/{name}", http.HandlerFunc(orgHandler.GetOrganizationByName)).Methods("GET")
	r.Handle("/public/api/v1/organizations/industry/{industry}", http.HandlerFunc(orgHandler.GetOrganizationsByIndustry)).Methods("GET")

	// Fiduciary & Superadmin can create/update/delete
	r.Handle("/api/v1/fiduciary/organizations", fiduciaryAuth(middlewares.RequirePermission("organizations:manage")(http.HandlerFunc(orgHandler.CreateOrganization)))).Methods("POST")
	r.Handle("/api/v1/fiduciary/organizations/{id}", fiduciaryAuth(middlewares.RequirePermission("organizations:manage")(http.HandlerFunc(orgHandler.UpdateOrganization)))).Methods("PUT")
	r.Handle("/api/v1/fiduciary/organizations/{id}", fiduciaryAuth(middlewares.RequirePermission("organizations:manage")(http.HandlerFunc(orgHandler.DeleteOrganization)))).Methods("DELETE")

	// ==== DATA PRINCIPAL MANAGEMENT BY FIDUCIARY ====
	adminUserRouter := r.PathPrefix("/api/v1/fiduciary/users").Subrouter()
	adminUserRouter.Use(fiduciaryAuth)
	adminUserRouter.HandleFunc("", handlers.FiduciaryCreateUserHandler(db.MasterDB, auditService)).Methods("POST")
	adminUserRouter.HandleFunc("/identify", handlers.IdentifyUserHandler(db.MasterDB)).Methods("POST")
	adminUserRouter.Handle("/{userId}/impersonate", requirePerm("users:impersonate")(handlers.ImpersonateUserHandler(db.MasterDB, auditService, privateKey, cfg.AdminTokenTTL))).Methods("POST")

	// ==== SIGNUP ====
	signupHandler := handlers.NewSignupHandler(db.MasterDB, cfg, orgService, emailService, auditService)
	r.HandleFunc("/api/v1/auth/user/signup", signupHandler.SignupDataPrincipal).Methods("POST")
	r.HandleFunc("/api/v1/auth/fiduciary/signup", signupHandler.SignupFiduciary).Methods("POST")
	r.HandleFunc("/api/v1/auth/verify-guardian", signupHandler.VerifyGuardian).Methods("GET")

	// ==== CONSENT ====
	consentHandler := handlers.NewConsentHandler(consentSvc, auditService) // TODO: This needs refactoring
	consentHandler.RegisterRoutes(r, db.MasterDB)                          // TODO: This needs refactoring

	// ==== PARTNER API ====
	partnerR := r.PathPrefix("/api/v1/partner").Subrouter()
	partnerR.HandleFunc("/consents", func(w http.ResponseWriter, r *http.Request) {
		apiKeyAuth(http.HandlerFunc(handlers.PartnerGetConsentsHandler)).ServeHTTP(w, r) // TODO: This needs refactoring
	}).Methods("GET")

	// ==== USER DSR ====
	DSRhandlers := handlers.NewDataRequestHandler(db.MasterDB, dsrService, auditService)
	r.Handle("/api/v1/user/requests", dataPrincipalAuth(http.HandlerFunc(DSRhandlers.ListUserRequests))).Methods("GET")
	r.Handle("/api/v1/user/requests", dataPrincipalAuth(http.HandlerFunc(DSRhandlers.CreateUserRequest))).Methods("POST")
	r.Handle("/api/v1/user/requests/{id}", dataPrincipalAuth(http.HandlerFunc(DSRhandlers.GetRequestDetails))).Methods("GET")

	// ==== FIDUCIARY DSR ====
	r.Handle("/api/v1/fiduciary/requests", fiduciaryAuth(middlewares.RequirePermission("consents:read")(http.HandlerFunc(DSRhandlers.ListAdminRequests)))).Methods("GET")
	r.Handle("/api/v1/fiduciary/requests/{id}", fiduciaryAuth(middlewares.RequirePermission("consents:read")(http.HandlerFunc(DSRhandlers.GetAdminRequestDetails)))).Methods("GET")
	r.Handle("/api/v1/fiduciary/requests/{id}/approve", fiduciaryAuth(middlewares.RequirePermission("consents:update")(http.HandlerFunc(DSRhandlers.ApproveRequest)))).Methods("POST")
	r.Handle("/api/v1/fiduciary/requests/{id}/reject", fiduciaryAuth(middlewares.RequirePermission("consents:update")(http.HandlerFunc(DSRhandlers.RejectRequest)))).Methods("POST")

	// ==== PURPOSES ====
	purposeHandler := handlers.NewPurposeHandler(db.MasterDB)
	purposeRouter := r.PathPrefix("/api/v1/fiduciary/purposes").Subrouter()
	purposeRouter.Use(fiduciaryAuth)
	purposeRouter.HandleFunc("", handlers.CreatePurposeHandler()).Methods("POST")
	purposeRouter.HandleFunc("", handlers.ListPurposesHandler()).Methods("GET")
	purposeRouter.HandleFunc("/{id}/toggle", purposeHandler.ToggleActive).Methods("POST")
	purposeRouter.HandleFunc("/{id}", handlers.UpdatePurposeHandler()).Methods("PUT")
	purposeRouter.HandleFunc("/{id}", handlers.DeletePurposeHandler()).Methods("DELETE")

	userPurposeRouter := r.PathPrefix("/api/v1/user/purposes").Subrouter()
	userPurposeRouter.Use(dataPrincipalAuth)
	userPurposeRouter.HandleFunc("/{id}", handlers.UserGetPurposeHandler()).Methods("GET")
	userPurposeRouter.HandleFunc("/tenant/{tenantID}", handlers.UserGetPurposeByTenant()).Methods("GET")

	// ==== API KEYS ====
	r.Handle("/api/v1/fiduciary/api-keys", fiduciaryAuth(middlewares.RequirePermission("api-keys:manage")(http.HandlerFunc(handlers.CreateAPIKeyHandler(db.MasterDB, publicKey))))).Methods("POST")
	r.Handle("/api/v1/fiduciary/api-keys", fiduciaryAuth(middlewares.RequirePermission("api-keys:manage")(http.HandlerFunc(handlers.ListAPIKeysHandler(db.MasterDB, publicKey))))).Methods("GET")
	r.Handle("/api/v1/fiduciary/api-keys/revoke", fiduciaryAuth(middlewares.RequirePermission("api-keys:manage")(http.HandlerFunc(handlers.RevokeAPIKeyHandler(db.MasterDB, publicKey))))).Methods("PUT")

	// ==== TENANT SETTINGS ====
	r.Handle("/api/v1/fiduciary/tenant/settings", fiduciaryAuth(middlewares.RequirePermission("roles:manage")(http.HandlerFunc(handlers.UpdateTenantSettingsHandler(db.MasterDB))))).Methods("PUT")

	// ==== AUDIT LOGS ====
	fiduciaryGR := r.PathPrefix("/api/v1/fiduciary").Subrouter()
	fiduciaryGR.Use(fiduciaryAuth)
	fiduciaryGR.Use(middlewares.RequirePermission("audit-logs:read"))
	fiduciaryGR.Use(handlers.TenantContextMiddleware)
	fiduciaryGR.HandleFunc("/audit/logs", handlers.GetTenantAuditLogsHandler()).Methods("GET")

	// ==== GRIEVANCES ====
	grievHandler := handlers.NewGrievanceHandler(notificationService, hub, auditService)
	r.Handle("/api/v1/dashboard/grievances", dataPrincipalAuth(http.HandlerFunc(grievHandler.Create))).Methods("POST")
	r.Handle("/api/v1/dashboard/grievances", dataPrincipalAuth(http.HandlerFunc(grievHandler.ListForUser))).Methods("GET")

	fiduciaryGR.Use(fiduciaryAuth)
	fiduciaryGR.Handle("/grievances", middlewares.RequirePermission("grievances:read")(http.HandlerFunc(grievHandler.List))).Methods("GET")
	fiduciaryGR.Handle("/grievances/{id}", middlewares.RequirePermission("grievances:respond")(http.HandlerFunc(grievHandler.Update))).Methods("PUT")

	// ===== Grievance Comments =====
	r.Handle("/api/v1/dashboard/grievances/{id}/comments", dataPrincipalAuth(http.HandlerFunc(grievHandler.AddComment))).Methods("POST")
	r.Handle("/api/v1/dashboard/grievances/{id}/comments", dataPrincipalAuth(http.HandlerFunc(grievHandler.GetComments))).Methods("GET")
	r.Handle("/api/v1/dashboard/grievances/comments/{commentID}", dataPrincipalAuth(http.HandlerFunc(grievHandler.DeleteComment))).Methods("DELETE")

	fiduciaryGR.Handle("/grievances/{id}/comments", middlewares.RequirePermission("grievances:respond")(http.HandlerFunc(grievHandler.AddComment))).Methods("POST")
	fiduciaryGR.Handle("/grievances/{id}/comments", middlewares.RequirePermission("grievances:read")(http.HandlerFunc(grievHandler.GetComments))).Methods("GET")
	fiduciaryGR.Handle("/grievances/comments/{commentID}", middlewares.RequirePermission("grievances:respond")(http.HandlerFunc(grievHandler.DeleteComment))).Methods("DELETE")

	// ==== VENDOR ====
	vendorRepo := repository.NewVendorRepository(db.MasterDB)
	vendorService := services.NewVendorService(vendorRepo)
	vendorHandler := handlers.NewVendorHandler(vendorService)

	// Public or all-authenticated users can list/get vendor details
	r.Handle("/api/v1/vendors", dataPrincipalAuth(http.HandlerFunc(vendorHandler.ListVendors))).Methods("GET")
	r.Handle("/api/v1/vendors/{id}", dataPrincipalAuth(http.HandlerFunc(vendorHandler.GetVendorByID))).Methods("GET")

	// Fiduciary & Superadmin can create/update/delete
	r.Handle("/api/v1/fiduciary/vendors", fiduciaryAuth(middlewares.RequirePermission("dpas:manage")(http.HandlerFunc(vendorHandler.CreateVendor)))).Methods("POST")
	r.Handle("/api/v1/fiduciary/vendors/{id}", fiduciaryAuth(middlewares.RequirePermission("dpas:manage")(http.HandlerFunc(vendorHandler.UpdateVendor)))).Methods("PUT")
	r.Handle("/api/v1/fiduciary/vendors/{id}", fiduciaryAuth(middlewares.RequirePermission("dpas:manage")(http.HandlerFunc(vendorHandler.DeleteVendor)))).Methods("DELETE")

	// ==== CONSENT FORMS ==== (managed by fiduciary)
	consentFormHandler := handlers.NewConsentFormHandler(consentFormSvc, auditService)
	consentFormRouter := r.PathPrefix("/api/v1/fiduciary/consent-forms").Subrouter()
	consentFormRouter.Use(fiduciaryAuth)
	consentFormRouter.HandleFunc("", http.HandlerFunc(consentFormHandler.CreateConsentForm)).Methods("POST")
	consentFormRouter.HandleFunc("", http.HandlerFunc(consentFormHandler.ListConsentForms)).Methods("GET")
	consentFormRouter.HandleFunc("/{formId}", http.HandlerFunc(consentFormHandler.GetConsentForm)).Methods("GET")
	consentFormRouter.HandleFunc("/{formId}", http.HandlerFunc(consentFormHandler.UpdateConsentForm)).Methods("PUT")
	consentFormRouter.HandleFunc("/{formId}", http.HandlerFunc(consentFormHandler.DeleteConsentForm)).Methods("DELETE")
	consentFormRouter.HandleFunc("/{formId}/purposes", http.HandlerFunc(consentFormHandler.AddPurposeToConsentForm)).Methods("POST")
	consentFormRouter.HandleFunc("/{formId}/purposes/{purposeId}", http.HandlerFunc(consentFormHandler.UpdatePurposeInConsentForm)).Methods("PUT")
	consentFormRouter.HandleFunc("/{formId}/purposes/{purposeId}", http.HandlerFunc(consentFormHandler.RemovePurposeFromConsentForm)).Methods("DELETE")
	consentFormRouter.HandleFunc("/{formId}/script", http.HandlerFunc(consentFormHandler.GetIntegrationScript)).Methods("GET")
	consentFormRouter.HandleFunc("/{formId}/publish", http.HandlerFunc(consentFormHandler.PublishConsentForm)).Methods("POST")
	consentFormRouter.HandleFunc("/{formId}/integration", http.HandlerFunc(consentFormHandler.GetIntegrationScript)).Methods("GET")

	// ==== PUBLIC CONSENT FLOW ====
	publicConsentHandler := handlers.NewPublicConsentHandler(userConsentSvc, consentFormSvc, webhookSvc)
	publicConsentRouter := r.PathPrefix("/api/v1/public/consent-forms").Subrouter()
	publicConsentRouter.Use(apiKeyAuth)
	publicConsentRouter.HandleFunc("/{formId}", http.HandlerFunc(publicConsentHandler.GetConsentForm)).Methods("GET")

	userConsentRouter := r.PathPrefix("/api/v1/user/consents").Subrouter()
	userConsentRouter.Use(dataPrincipalAuth)
	userConsentRouter.Handle("/submit/{formId}", http.HandlerFunc(publicConsentHandler.SubmitConsent)).Methods("POST")
	userConsentRouter.Handle("", http.HandlerFunc(publicConsentHandler.GetUserConsents)).Methods("GET")
	userConsentRouter.Handle("/withdraw/{purposeId}", http.HandlerFunc(publicConsentHandler.WithdrawConsent)).Methods("POST")
	userConsentRouter.Handle("/{purposeId}", http.HandlerFunc(publicConsentHandler.GetUserConsentForPurpose)).Methods("GET")

	// ==== NOTIFICATION PREFERENCES ====
	notificationPreferencesHandler := handlers.NewNotificationPreferencesHandler(notificationPreferencesService)
	notificationPreferencesRouter := r.PathPrefix("/api/v1/user/notification-preferences").Subrouter()
	notificationPreferencesRouter.Use(dataPrincipalAuth)
	notificationPreferencesRouter.Handle("", http.HandlerFunc(notificationPreferencesHandler.Get)).Methods("GET")
	notificationPreferencesRouter.Handle("", http.HandlerFunc(notificationPreferencesHandler.Update)).Methods("PUT")

	// ==== FIDUCIARY MANAGEMENT ====
	fiduciaryManagementRouter := r.PathPrefix("/api/v1/fiduciaries").Subrouter()
	fiduciaryManagementRouter.Use(fiduciaryAuth, middlewares.RequirePermission("users:read", "users:create", "users:update", "users:delete"))
	fiduciaryManagementRouter.HandleFunc("", handlers.ListAllFiduciariesHandler(fiduciaryService)).Methods("GET")
	fiduciaryManagementRouter.HandleFunc("", handlers.CreateNewFiduciaryHandler(fiduciaryService)).Methods("POST")
	fiduciaryManagementRouter.HandleFunc("/stats", handlers.FiduciaryStatsHandler(fiduciaryService)).Methods("GET")
	fiduciaryManagementRouter.HandleFunc("/{fiduciaryId}", handlers.GetFiduciaryByIDHandler(fiduciaryService)).Methods("GET")
	fiduciaryManagementRouter.HandleFunc("/{fiduciaryId}", handlers.UpdateFiduciaryDataHandler(fiduciaryService)).Methods("PUT")
	fiduciaryManagementRouter.HandleFunc("/{fiduciaryId}", handlers.DeleteFiduciaryByIDHandler(fiduciaryService)).Methods("DELETE")

	// === CONSENT MANAGEMENT FOR FIDUCIARY ===
	consentManagementRouter := r.PathPrefix("/api/v1/fiduciary/consents").Subrouter()
	consentManagementRouter.Use(fiduciaryAuth)
	consentManagementRouter.HandleFunc("", handlers.ListConsentsHandler(consentSvc)).Methods("GET")
	consentManagementRouter.HandleFunc("/stats", consentHandler.GetConsentStats).Methods("GET")
	consentManagementRouter.HandleFunc("/{consentId}", handlers.GetConsentByIDHandler(consentSvc)).Methods("GET")

	// ==== BREACH NOTIFICATIONS ====
	breachNotificationHandler := handlers.NewBreachNotificationHandler(breachNotificationSvc, auditService)
	breachNotificationRouter := r.PathPrefix("/api/v1/fiduciary/breach-notifications").Subrouter()
	breachNotificationRouter.Use(fiduciaryAuth, middlewares.RequirePermission("breaches:manage"))
	breachNotificationRouter.Handle("", http.HandlerFunc(breachNotificationHandler.CreateBreachNotification)).Methods("POST")
	breachNotificationRouter.Handle("", http.HandlerFunc(breachNotificationHandler.ListBreachNotifications)).Methods("GET")
	breachNotificationRouter.Handle("/stats", http.HandlerFunc(breachNotificationHandler.GetBreachStats)).Methods("GET")
	breachNotificationRouter.Handle("/{notificationId}", http.HandlerFunc(breachNotificationHandler.GetBreachNotification)).Methods("GET")
	breachNotificationRouter.Handle("/{notificationId}", http.HandlerFunc(breachNotificationHandler.UpdateBreachNotification)).Methods("PUT")
	breachNotificationRouter.Handle("/{notificationId}", http.HandlerFunc(breachNotificationHandler.DeleteBreachNotification)).Methods("DELETE")

	// ==== DATA PROCESSING AGREEMENTS ====
	dpaHandler := handlers.NewDPAHandler(db.MasterDB, auditService)
	dpaRouter := r.PathPrefix("/api/v1/fiduciary/dpas").Subrouter()
	dpaRouter.Use(fiduciaryAuth, middlewares.RequirePermission("dpas:manage"))
	dpaHandler.RegisterRoutes(dpaRouter)

	// ==== RBAC MANAGEMENT (Roles, Permissions) ====
	rbacHandler := handlers.NewRBACHandler(db.MasterDB)
	rbacRouter := r.PathPrefix("/api/v1/fiduciary").Subrouter()
	rbacRouter.Use(fiduciaryAuth, middlewares.RequirePermission("roles:manage"))
	rbacRouter.HandleFunc("/permissions", rbacHandler.ListPermissions).Methods("GET")
	rbacRouter.HandleFunc("/roles", rbacHandler.ListRoles).Methods("GET")
	rbacRouter.HandleFunc("/roles", rbacHandler.CreateRole).Methods("POST")
	rbacRouter.HandleFunc("/roles/{roleId}", rbacHandler.UpdateRole).Methods("PUT")
	rbacRouter.HandleFunc("/roles/{roleId}", rbacHandler.DeleteRole).Methods("DELETE")
	rbacRouter.HandleFunc("/users/{userId}/roles", rbacHandler.AssignRolesToUser).Methods("PUT")

	// ==== PUBLIC API ====
	publicApiRouter := r.PathPrefix("/api/v1/public").Subrouter()
	publicApiRouter.Use(apiKeyAuth)
	publicAPIHandler := handlers.NewPublicAPIHandler(db.MasterDB, dsrService, userConsentSvc, auditService, webhookSvc)
	publicApiRouter.HandleFunc("/users", publicAPIHandler.CreateDataPrincipal).Methods("POST")
	publicApiRouter.HandleFunc("/users/{userId}/consents", publicAPIHandler.GetDataPrincipalConsents).Methods("GET")
	publicApiRouter.HandleFunc("/consents/verify", publicAPIHandler.VerifyConsents).Methods("POST")
	publicApiRouter.HandleFunc("/consents/submit", publicAPIHandler.SubmitConsentViaAPI).Methods("POST")
	publicApiRouter.HandleFunc("/dsr", publicAPIHandler.CreateDSR).Methods("POST")

	// ==== WEBHOOK MANAGEMENT ====
	webhookHandler := handlers.NewWebhookHandler(db.MasterDB)
	webhookRouter := r.PathPrefix("/api/v1/fiduciary/webhooks").Subrouter()
	webhookRouter.Use(fiduciaryAuth, middlewares.RequirePermission("roles:manage")) // Reuse a high-level permission
	webhookRouter.HandleFunc("", webhookHandler.CreateWebhook).Methods("POST")
	webhookRouter.HandleFunc("", webhookHandler.ListWebhooks).Methods("GET")
	webhookRouter.HandleFunc("/{webhookId}", webhookHandler.DeleteWebhook).Methods("DELETE")

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
