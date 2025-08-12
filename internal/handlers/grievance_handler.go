// internal/handlers/grievance_handler.go
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/realtime"
	"consultrnr/consent-manager/internal/repository"
	"consultrnr/consent-manager/internal/services"
)

type GrievanceHandler struct {
	notificationService *services.NotificationService
	hub                 *realtime.Hub
	auditService        *services.AuditService
}

func NewGrievanceHandler(
	notificationService *services.NotificationService,
	hub *realtime.Hub,
	auditService *services.AuditService,
) *GrievanceHandler {
	return &GrievanceHandler{notificationService: notificationService, hub: hub, auditService: auditService}
}

// ===== Helper functions to get per-request service =====
func (h *GrievanceHandler) perRequestSvc(r *http.Request) (*services.GrievanceService, string, error) {
	dbTenant, tenantID, err := getTenantDBForRequest(r)
	if err != nil {
		return nil, "", err
	}
	repo := repository.NewGrievanceRepo(dbTenant)
	return services.NewGrievanceService(repo), tenantID, nil
}

func (h *GrievanceHandler) perAdminRequestSvc(r *http.Request) (*services.GrievanceService, string, error) {
	dbTenant, tenantID, err := getAdminTenantDBForRequest(r)
	if err != nil {
		return nil, "", err
	}
	repo := repository.NewGrievanceRepo(dbTenant)
	return services.NewGrievanceService(repo), tenantID, nil
}

// ================== CREATE ==================
func (h *GrievanceHandler) Create(w http.ResponseWriter, r *http.Request) {
	svc, tenantID, err := h.perRequestSvc(r)
	if err != nil {
		http.Error(w, "Invalid tenant or DB", http.StatusBadRequest)
		return
	}

	var req dto.CreateGrievanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.TenantID = tenantID // trust server context

		userIDStr := middlewares.GetDataPrincipalID(r.Context())
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	g, err := svc.Raise(r.Context(), req, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Audit log
	go h.auditService.Create(r.Context(), userID, uuid.MustParse(tenantID), uuid.Nil, "grievance_created", "", userID.String(), r.RemoteAddr, "", "", map[string]interface{}{"grievance_id": g.ID})

	go h.notify(r.Context(), userID,
		"Grievance submitted",
		"We received your grievance and will keep you posted.",
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(g)
}

// ================== GET BY ID ==================
func (h *GrievanceHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	svc, _, err := h.perAdminRequestSvc(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.Context().Value("grievanceID").(string)
	g, err := svc.GetByID(r.Context(), id)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "grievance not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(g)
}

// ================== LIST ==================
func (h *GrievanceHandler) List(w http.ResponseWriter, r *http.Request) {
	svc, tenantID, err := h.perAdminRequestSvc(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	status := r.URL.Query().Get("status")
	var st *string
	if status != "" {
		st = &status
	}
	list, err := svc.List(r.Context(), tenantID, st)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "no grievances found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"grievances": list})
}

// ================== LIST FOR USER ==================
func (h *GrievanceHandler) ListForUser(w http.ResponseWriter, r *http.Request) {
	svc, _, err := h.perRequestSvc(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	userIDStr := middlewares.GetDataPrincipalID(r.Context())
	list, err := svc.ListForUser(r.Context(), userIDStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"grievances": list})
}

// ================== UPDATE STATUS ==================
func (h *GrievanceHandler) Update(w http.ResponseWriter, r *http.Request) {
	svc, _, err := h.perAdminRequestSvc(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.Context().Value("grievanceID").(string)

	var req dto.UpdateGrievanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := svc.Resolve(r.Context(), id, req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ================== UPDATE DETAILS ==================
func (h *GrievanceHandler) UpdateDetails(w http.ResponseWriter, r *http.Request) {
	svc, _, err := h.perAdminRequestSvc(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.Context().Value("grievanceID").(string)

	var req dto.UpdateGrievanceDetailsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := svc.UpdateDetails(r.Context(), id, req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ================== DELETE ==================
func (h *GrievanceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	svc, _, err := h.perAdminRequestSvc(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.Context().Value("grievanceID").(string)
	if err := svc.Delete(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ================== ADD COMMENT (CHAT) ==================
func (h *GrievanceHandler) AddComment(w http.ResponseWriter, r *http.Request) {
	svc, _, err := h.perRequestSvc(r) // Both admin and user can use this
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var req dto.CreateGrievanceCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	comment, err := svc.AddComment(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(comment)
}

// ================== LIST COMMENTS ==================
func (h *GrievanceHandler) GetComments(w http.ResponseWriter, r *http.Request) {
	svc, _, err := h.perRequestSvc(r) // Both admin and user
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	grievanceID := r.Context().Value("grievanceID").(string)
	comments, err := svc.GetComments(r.Context(), grievanceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"comments": comments})
}

// ================== DELETE COMMENT ==================
func (h *GrievanceHandler) DeleteComment(w http.ResponseWriter, r *http.Request) {
	svc, _, err := h.perAdminRequestSvc(r) // Usually admin-only
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	commentID := r.Context().Value("commentID").(string)
	if err := svc.DeleteComment(r.Context(), commentID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ================== NOTIFY ==================
func (h *GrievanceHandler) notify(ctx context.Context, user uuid.UUID, title, body string) {
	n := models.Notification{
		UserID:    user,
		Title:     title,
		Body:      body,
		Icon:      "bell",
		Unread:    true,
		CreatedAt: time.Now(),
	}
	h.notificationService.Create(ctx, &n)
}