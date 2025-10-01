package handlers

import (
	"consultrnr/consent-manager/internal/claims"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"
	"consultrnr/consent-manager/internal/services"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type OrganizationHandler struct {
	service *services.OrganizationService
	repo    *repository.OrganizationRepository
}

func NewOrganizationHandler(service *services.OrganizationService, repo *repository.OrganizationRepository) *OrganizationHandler {
	return &OrganizationHandler{service: service, repo: repo}
}

func (h *OrganizationHandler) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	var org models.OrganizationEntity
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	claims, ok := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if !ok || claims == nil {
		http.Error(w, "fiduciary claims not found", http.StatusUnauthorized)
		return
	}
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		http.Error(w, "invalid tenant id in claims", http.StatusBadRequest)
		return
	}

	// Assign TenantID from context and generate a new ID for the organization
	org.TenantID = tenantID
	org.ID = uuid.New()

	if err := h.service.CreateOrganization(&org); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(org)
}

func (h *OrganizationHandler) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	var org models.OrganizationEntity
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.service.UpdateOrganization(&org); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(org)
}

func (h *OrganizationHandler) DeleteOrganization(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idParam, ok := vars["id"]
	if !ok {
		http.Error(w, "missing id from path", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(idParam)
	if err != nil {
		http.Error(w, "invalid id format", http.StatusBadRequest)
		return
	}

	if err := h.service.DeleteOrganization(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *OrganizationHandler) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.service.ListOrganizations()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(orgs)
}

func (h *OrganizationHandler) GetOrganizationByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idParam, ok := vars["id"]
	if !ok {
		http.Error(w, "missing id from path", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(idParam)
	if err != nil {
		http.Error(w, "invalid id format", http.StatusBadRequest)
		return
	}

	org, err := h.service.GetOrganizationByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(org)
}

func (h *OrganizationHandler) GetOrganizationByName(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name parameter", http.StatusBadRequest)
		return
	}
	org, err := h.service.GetOrganizationByName(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(org)
}

func (h *OrganizationHandler) GetOrganizationsByIndustry(w http.ResponseWriter, r *http.Request) {
	industry := r.URL.Query().Get("industry")
	if industry == "" {
		http.Error(w, "missing industry parameter", http.StatusBadRequest)
		return
	}
	orgs, err := h.service.GetOrganizationsByIndustry(industry)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(orgs)
}
