package handlers

import (
	"consultrnr/consent-manager/internal/claims"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/services"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type ConsentFormHandler struct {
	service      *services.ConsentFormService
	AuditService *services.AuditService
}

func NewConsentFormHandler(service *services.ConsentFormService, auditService *services.AuditService) *ConsentFormHandler {
	return &ConsentFormHandler{service: service, AuditService: auditService}
}

func (h *ConsentFormHandler) CreateConsentForm(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if !ok {
		writeError(w, http.StatusForbidden, "fiduciary access required")
		return
	}
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID in claims")
		return
	}

	var req dto.CreateConsentFormRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	form, err := h.service.CreateConsentForm(tenantID, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for consent form creation
	if h.AuditService != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, form.ID, "consent_form_created", "created", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"title":       form.Title,
			"description": form.Description,
		})
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(form)
}

func (h *ConsentFormHandler) UpdateConsentForm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}

	var req dto.UpdateConsentFormRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	form, err := h.service.UpdateConsentForm(formID, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for consent form update
	claims, _ := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		tenantID, _ := uuid.Parse(claims.TenantID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, formID, "consent_form_updated", "updated", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"title":       form.Title,
			"description": form.Description,
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(form)
}

func (h *ConsentFormHandler) DeleteConsentForm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}

	if err := h.service.DeleteConsentForm(formID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for consent form deletion
	claims, _ := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		tenantID, _ := uuid.Parse(claims.TenantID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, formID, "consent_form_deleted", "deleted", claims.FiduciaryID, r.RemoteAddr, "", "", nil)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ConsentFormHandler) GetConsentForm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}

	form, err := h.service.GetConsentFormByID(formID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for consent form access
	claims, _ := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		tenantID, _ := uuid.Parse(claims.TenantID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, formID, "consent_form_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"title": form.Title,
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(form)
}

func (h *ConsentFormHandler) ListConsentForms(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if !ok {
		writeError(w, http.StatusForbidden, "fiduciary access required")
		return
	}
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tenant ID in claims")
		return
	}

	forms, err := h.service.ListConsentForms(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for consent forms list access
	if h.AuditService != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, tenantID, "consent_forms_list_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"count": len(forms),
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(forms)
}

func (h *ConsentFormHandler) AddPurposeToConsentForm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}

	var req dto.AddPurposeToConsentFormRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	formPurpose, err := h.service.AddPurposeToConsentForm(formID, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for adding purpose to consent form
	claims, _ := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		tenantID, _ := uuid.Parse(claims.TenantID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, formID, "purpose_added_to_consent_form", "updated", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"purpose_id": req.PurposeID,
		})
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(formPurpose)
}

func (h *ConsentFormHandler) UpdatePurposeInConsentForm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}
	purposeID, err := uuid.Parse(vars["purposeId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid purpose ID")
		return
	}

	var req dto.UpdatePurposeInConsentFormRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	formPurpose, err := h.service.UpdatePurposeInConsentForm(formID, purposeID, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for updating purpose in consent form
	claims, _ := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		tenantID, _ := uuid.Parse(claims.TenantID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, formID, "purpose_updated_in_consent_form", "updated", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"purpose_id": purposeID,
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(formPurpose)
}

func (h *ConsentFormHandler) RemovePurposeFromConsentForm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}
	purposeID, err := uuid.Parse(vars["purposeId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid purpose ID")
		return
	}

	if err := h.service.RemovePurposeFromConsentForm(formID, purposeID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for removing purpose from consent form
	claims, _ := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		tenantID, _ := uuid.Parse(claims.TenantID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, formID, "purpose_removed_from_consent_form", "updated", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"purpose_id": purposeID,
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ConsentFormHandler) GetIntegrationScript(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}

	// Audit logging for getting integration script
	claims, _ := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		tenantID, _ := uuid.Parse(claims.TenantID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, formID, "integration_script_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"form_id": formID,
		})
	}

	script := h.service.GetIntegrationScript(formID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(script)
}

func (h *ConsentFormHandler) PublishConsentForm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}

	if err := h.service.PublishConsentForm(formID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit logging for publishing consent form
	claims, _ := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*claims.FiduciaryClaims)
	if h.AuditService != nil && claims != nil {
		fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
		tenantID, _ := uuid.Parse(claims.TenantID)
		go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, formID, "consent_form_published", "published", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
			"form_id": formID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "form published successfully"})
}
