package handlers

import (
	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/services"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type PublicConsentHandler struct {
	userConsentService *services.UserConsentService
	consentFormService *services.ConsentFormService
}

func NewPublicConsentHandler(userConsentService *services.UserConsentService, consentFormService *services.ConsentFormService) *PublicConsentHandler {
	return &PublicConsentHandler{userConsentService: userConsentService, consentFormService: consentFormService}
}

func (h *PublicConsentHandler) GetConsentForm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}

	form, err := h.consentFormService.GetConsentFormByID(formID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, form)
}

func (h *PublicConsentHandler) SubmitConsent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	formID, err := uuid.Parse(vars["formId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form ID")
		return
	}

	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "User claims not found")
		return
	}

	userID, err := uuid.Parse(claims.PrincipalID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID in claims")
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID in claims")
		return
	}

	var req dto.SubmitConsentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.userConsentService.SubmitConsent(userID, tenantID, formID, &req); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *PublicConsentHandler) GetUserConsents(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "User claims not found")
		return
	}

	userID, err := uuid.Parse(claims.PrincipalID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID in claims")
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID in claims")
		return
	}

	consents, err := h.userConsentService.GetUserConsents(userID, tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, consents)
}

func (h *PublicConsentHandler) WithdrawConsent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	purposeID, err := uuid.Parse(vars["purposeId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid purpose ID")
		return
	}

	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "User claims not found")
		return
	}

	userID, err := uuid.Parse(claims.PrincipalID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID in claims")
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID in claims")
		return
	}

	if err := h.userConsentService.WithdrawConsent(userID, purposeID, tenantID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *PublicConsentHandler) GetUserConsentForPurpose(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	purposeID, err := uuid.Parse(vars["purposeId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid purpose ID")
		return
	}

	claims, ok := r.Context().Value(contextkeys.UserClaimsKey).(*auth.DataPrincipalClaims)
	if !ok {
		writeError(w, http.StatusUnauthorized, "User claims not found")
		return
	}

	userID, err := uuid.Parse(claims.PrincipalID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID in claims")
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID in claims")
		return
	}

	consent, err := h.userConsentService.GetUserConsentForPurpose(userID, purposeID, tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, consent)
}
