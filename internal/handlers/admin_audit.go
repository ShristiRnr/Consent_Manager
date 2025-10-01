package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"consultrnr/consent-manager/internal/claims"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
)

// these keys should match what your middleware uses to inject data into context
type ctxKey string

const (
	tenantIDKey ctxKey = "tenantID"
	tenantDBKey ctxKey = "tenantDB"
)

func GetTenantAuditLogsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Retrieve tenant ID and DB from request.Context
		tenantIDStr, ok1 := r.Context().Value(tenantIDKey).(string)
		tenantDB, ok2 := r.Context().Value(tenantDBKey).(*gorm.DB)
		if !ok1 || !ok2 || tenantIDStr == "" || tenantDB == nil {
			http.Error(w, "Invalid tenant context", http.StatusBadRequest)
			return
		}

		// Parse & validate tenant UUID
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			http.Error(w, "Invalid tenant ID format", http.StatusBadRequest)
			return
		}

		// limit query param (default 50, max 200)
		limit := 50
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}

		// build GORM query
		var logs []models.AuditLog
		q := tenantDB.
			Order("timestamp DESC").
			Limit(limit).
			Where("tenant_id = ?", tenantID)

		if userID := r.URL.Query().Get("user_id"); userID != "" {
			q = q.Where("user_id = ?", userID)
		}
		if action := r.URL.Query().Get("action_type"); action != "" {
			q = q.Where("action_type = ?", action)
		}

		if err := q.Find(&logs).Error; err != nil {
			http.Error(w, "Failed to load logs", http.StatusInternalServerError)
			return
		}

		// return JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	}
}

// middleware to inject tenantID and *gorm.DB into context
func TenantContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
		if !ok || claims.TenantID == "" {
			http.Error(w, "Unauthorized: missing tenant claim", http.StatusUnauthorized)
			return
		}
		tenantID := claims.TenantID
		schema := "tenant_" + tenantID[:8]
		tenantDB, err := db.GetTenantDB(schema)
		if err != nil || tenantDB == nil {
			http.Error(w, "Tenant DB not found", http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(r.Context(), tenantIDKey, tenantID)
		ctx = context.WithValue(ctx, tenantDBKey, tenantDB)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
