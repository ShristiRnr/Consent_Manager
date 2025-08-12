package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"consultrnr/consent-manager/internal/dpa"
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"
	"consultrnr/consent-manager/internal/services"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// DPAHandler handles Data Processing Agreement related requests
type DPAHandler struct {
	DB            *gorm.DB
	EncryptedRepo *repository.EncryptedDPARepository
	AuditService  *services.AuditService
}

// NewDPAHandler creates a new DPA handler
func NewDPAHandler(db *gorm.DB, auditService *services.AuditService) *DPAHandler {
	return &DPAHandler{DB: db, EncryptedRepo: repository.NewEncryptedDPARepository(db), AuditService: auditService}
}

// RegisterRoutes registers DPA-related routes
func (h *DPAHandler) RegisterRoutes(r *mux.Router) {
	// DPA management routes
	r.HandleFunc("", h.CreateDPA).Methods("POST")
	r.HandleFunc("/{id}", h.GetDPA).Methods("GET")
	r.HandleFunc("/{id}", h.UpdateDPA).Methods("PUT")
	r.HandleFunc("/{id}/terminate", h.TerminateDPA).Methods("POST")
	r.HandleFunc("", h.ListDPAs).Methods("GET")
	r.HandleFunc("/vendor/{vendorId}", h.GetDPAsByVendor).Methods("GET")
	r.HandleFunc("/tenant/{tenantId}", h.GetDPAsByTenant).Methods("GET")
	r.HandleFunc("/{id}/compliance", h.CreateComplianceCheck).Methods("POST")
	r.HandleFunc("/{id}/compliance", h.GetComplianceChecks).Methods("GET")
}

// CreateDPA creates a new Data Processing Agreement
func (h *DPAHandler) CreateDPA(w http.ResponseWriter, r *http.Request) {
	var dpaRequest struct {
		TenantID             string   `json:"tenantId"`
		VendorID             string   `json:"vendorId"`
		AgreementTitle       string   `json:"agreementTitle"`
		AgreementNumber      string   `json:"agreementNumber"`
		EffectiveDate        string   `json:"effectiveDate"`
		ExpiryDate           *string  `json:"expiryDate,omitempty"`
		ProcessingPurposes   []string `json:"processingPurposes"`
		DataCategories       []string `json:"dataCategories"`
		ProcessingLocation   string   `json:"processingLocation"`
		SubProcessingAllowed bool     `json:"subProcessingAllowed"`
		SecurityMeasures     []string `json:"securityMeasures"`
		DataRetentionPeriod  string   `json:"dataRetentionPeriod"`
		DataSubjectRights    []string `json:"dataSubjectRights"`
		BreachNotification   bool     `json:"breachNotification"`
		AuditRights          bool     `json:"auditRights"`
		LiabilityCap         string   `json:"liabilityCap"`
		InsuranceCoverage    string   `json:"insuranceCoverage"`
		GoverningLaw         string   `json:"governingLaw"`
		SignatoryName        string   `json:"signatoryName"`
		SignatoryTitle       string   `json:"signatoryTitle"`
		Version              string   `json:"version"`
	}

	if err := json.NewDecoder(r.Body).Decode(&dpaRequest); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	tenantID, err := uuid.Parse(dpaRequest.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID")
		return
	}

	vendorID, err := uuid.Parse(dpaRequest.VendorID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid vendor ID")
		return
	}

	effectiveDate, err := time.Parse("2006-01-02", dpaRequest.EffectiveDate)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid effective date format")
		return
	}

	var expiryDate *time.Time
	if dpaRequest.ExpiryDate != nil {
		ed, err := time.Parse("2006-01-02", *dpaRequest.ExpiryDate)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid expiry date format")
			return
		}
		expiryDate = &ed
	}

	// Convert string slices to proper types
	var processingPurposes []dpa.ProcessingPurpose
	for _, p := range dpaRequest.ProcessingPurposes {
		processingPurposes = append(processingPurposes, dpa.ProcessingPurpose(p))
	}

	var dataCategories []dpa.DataCategory
	for _, c := range dpaRequest.DataCategories {
		dataCategories = append(dataCategories, dpa.DataCategory(c))
	}

	var securityMeasures []dpa.SecurityMeasure
	for _, s := range dpaRequest.SecurityMeasures {
		securityMeasures = append(securityMeasures, dpa.SecurityMeasure(s))
	}

	// Create the DPA
	dpaModel := models.DataProcessingAgreement{
		ID:                   uuid.New(),
		TenantID:             tenantID,
		VendorID:             vendorID,
		AgreementTitle:       dpaRequest.AgreementTitle,
		AgreementNumber:      dpaRequest.AgreementNumber,
		Status:               string(dpa.DPAStatusPending),
		EffectiveDate:        effectiveDate,
		ExpiryDate:           expiryDate,
		ProcessingPurposes:   datatypes.JSON{},
		DataCategories:       datatypes.JSON{},
		ProcessingLocation:   dpaRequest.ProcessingLocation,
		SubProcessingAllowed: dpaRequest.SubProcessingAllowed,
		SecurityMeasures:     datatypes.JSON{},
		DataRetentionPeriod:  dpaRequest.DataRetentionPeriod,
		DataSubjectRights:    datatypes.JSON{},
		BreachNotification:   dpaRequest.BreachNotification,
		AuditRights:          dpaRequest.AuditRights,
		LiabilityCap:         dpaRequest.LiabilityCap,
		InsuranceCoverage:    dpaRequest.InsuranceCoverage,
		GoverningLaw:         dpaRequest.GoverningLaw,
		SignatoryName:        dpaRequest.SignatoryName,
		SignatoryTitle:       dpaRequest.SignatoryTitle,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
		Version:              dpaRequest.Version,
	}

	// Convert JSON data back to slices for DPA entity
	var entityProcessingPurposes []dpa.ProcessingPurpose
	if len(dpaModel.ProcessingPurposes) > 0 {
		if err := json.Unmarshal(dpaModel.ProcessingPurposes, &entityProcessingPurposes); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to unmarshal processing purposes")
			return
		}
	}

	var entityDataCategories []dpa.DataCategory
	if len(dpaModel.DataCategories) > 0 {
		if err := json.Unmarshal(dpaModel.DataCategories, &entityDataCategories); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to unmarshal data categories")
			return
		}
	}

	var entitySecurityMeasures []dpa.SecurityMeasure
	if len(dpaModel.SecurityMeasures) > 0 {
		if err := json.Unmarshal(dpaModel.SecurityMeasures, &entitySecurityMeasures); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to unmarshal security measures")
			return
		}
	}

	var entityDataSubjectRights []string
	if len(dpaModel.DataSubjectRights) > 0 {
		if err := json.Unmarshal(dpaModel.DataSubjectRights, &entityDataSubjectRights); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to unmarshal data subject rights")
			return
		}
	}

	// Validate the DPA
	dpaEntity := dpa.DataProcessingAgreement{
		ID:                   dpaModel.ID,
		TenantID:             dpaModel.TenantID,
		VendorID:             dpaModel.VendorID,
		AgreementTitle:       dpaModel.AgreementTitle,
		AgreementNumber:      dpaModel.AgreementNumber,
		Status:               dpa.DPAStatus(dpaModel.Status),
		EffectiveDate:        dpaModel.EffectiveDate,
		ExpiryDate:           dpaModel.ExpiryDate,
		ProcessingPurposes:   entityProcessingPurposes,
		DataCategories:       entityDataCategories,
		ProcessingLocation:   dpaModel.ProcessingLocation,
		SubProcessingAllowed: dpaModel.SubProcessingAllowed,
		SecurityMeasures:     entitySecurityMeasures,
		DataRetentionPeriod:  dpaModel.DataRetentionPeriod,
		DataSubjectRights:    entityDataSubjectRights,
		BreachNotification:   dpaModel.BreachNotification,
		AuditRights:          dpaModel.AuditRights,
		LiabilityCap:         dpaModel.LiabilityCap,
		InsuranceCoverage:    dpaModel.InsuranceCoverage,
		GoverningLaw:         dpaModel.GoverningLaw,
		SignatoryName:        dpaModel.SignatoryName,
		SignatoryTitle:       dpaModel.SignatoryTitle,
		SignedDate:           dpaModel.SignedDate,
		CreatedAt:            dpaModel.CreatedAt,
		UpdatedAt:            dpaModel.UpdatedAt,
		Version:              dpaModel.Version,
		PreviousVersionID:    dpaModel.PreviousVersionID,
	}

	if violations := dpaEntity.Validate(); len(violations) > 0 {
		writeError(w, http.StatusBadRequest, "DPA validation failed: "+services.JoinStrings(violations, ", "))
		return
	}

	// Save to database using encrypted repository
	if err := h.EncryptedRepo.CreateDPA(&dpaModel); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create DPA")
		return
	}

	// Audit logging for DPA creation
	if h.AuditService != nil {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims != nil {
			fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "dpa_created", "created", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"dpa_id":          dpaModel.ID.String(),
				"vendor_id":       dpaModel.VendorID.String(),
				"agreement_title": dpaRequest.AgreementTitle,
			})
		}
	}

	writeJSON(w, http.StatusCreated, dpaModel)
}

// GetDPA retrieves a specific Data Processing Agreement
func (h *DPAHandler) GetDPA(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dpaID, err := uuid.Parse(vars["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DPA ID")
		return
	}

	dpaModel, err := h.EncryptedRepo.GetDPAByID(dpaID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			writeError(w, http.StatusNotFound, "DPA not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve DPA")
		return
	}

	// Audit logging for DPA access
	if h.AuditService != nil {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims != nil {
			fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "dpa_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"dpa_id":          dpaModel.ID.String(),
				"vendor_id":       dpaModel.VendorID.String(),
				"agreement_title": dpaModel.AgreementTitle,
			})
		}
	}

	writeJSON(w, http.StatusOK, dpaModel)
}

// UpdateDPA updates an existing Data Processing Agreement
func (h *DPAHandler) UpdateDPA(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dpaID, err := uuid.Parse(vars["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DPA ID")
		return
	}

	dpaModel, err := h.EncryptedRepo.GetDPAByID(dpaID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			writeError(w, http.StatusNotFound, "DPA not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve DPA")
		return
	}

	var dpaRequest struct {
		AgreementTitle       *string  `json:"agreementTitle,omitempty"`
		AgreementNumber      *string  `json:"agreementNumber,omitempty"`
		Status               *string  `json:"status,omitempty"`
		EffectiveDate        *string  `json:"effectiveDate,omitempty"`
		ExpiryDate           *string  `json:"expiryDate,omitempty"`
		ProcessingPurposes   []string `json:"processingPurposes,omitempty"`
		DataCategories       []string `json:"dataCategories,omitempty"`
		ProcessingLocation   *string  `json:"processingLocation,omitempty"`
		SubProcessingAllowed *bool    `json:"subProcessingAllowed,omitempty"`
		SecurityMeasures     []string `json:"securityMeasures,omitempty"`
		DataRetentionPeriod  *string  `json:"dataRetentionPeriod,omitempty"`
		DataSubjectRights    []string `json:"dataSubjectRights,omitempty"`
		BreachNotification   *bool    `json:"breachNotification,omitempty"`
		AuditRights          *bool    `json:"auditRights,omitempty"`
		LiabilityCap         *string  `json:"liabilityCap,omitempty"`
		InsuranceCoverage    *string  `json:"insuranceCoverage,omitempty"`
		GoverningLaw         *string  `json:"governingLaw,omitempty"`
		SignatoryName        *string  `json:"signatoryName,omitempty"`
		SignatoryTitle       *string  `json:"signatoryTitle,omitempty"`
		Signature            *string  `json:"signature,omitempty"`
		SignedDate           *string  `json:"signedDate,omitempty"`
		Version              *string  `json:"version,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&dpaRequest); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Update fields if provided
	if dpaRequest.AgreementTitle != nil {
		dpaModel.AgreementTitle = *dpaRequest.AgreementTitle
	}
	if dpaRequest.AgreementNumber != nil {
		dpaModel.AgreementNumber = *dpaRequest.AgreementNumber
	}
	if dpaRequest.Status != nil {
		dpaModel.Status = *dpaRequest.Status
	}
	if dpaRequest.EffectiveDate != nil {
		effectiveDate, err := time.Parse("2006-01-02", *dpaRequest.EffectiveDate)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid effective date format")
			return
		}
		dpaModel.EffectiveDate = effectiveDate
	}
	if dpaRequest.ExpiryDate != nil {
		ed, err := time.Parse("2006-01-02", *dpaRequest.ExpiryDate)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid expiry date format")
			return
		}
		dpaModel.ExpiryDate = &ed
	}
	if len(dpaRequest.ProcessingPurposes) > 0 {
		var processingPurposes []dpa.ProcessingPurpose
		for _, p := range dpaRequest.ProcessingPurposes {
			processingPurposes = append(processingPurposes, dpa.ProcessingPurpose(p))
		}
		// Convert slice to JSON
		processingPurposesJSON, err := json.Marshal(processingPurposes)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to marshal processing purposes")
			return
		}
		dpaModel.ProcessingPurposes = datatypes.JSON(processingPurposesJSON)
	}
	if len(dpaRequest.DataCategories) > 0 {
		var dataCategories []dpa.DataCategory
		for _, c := range dpaRequest.DataCategories {
			dataCategories = append(dataCategories, dpa.DataCategory(c))
		}
		// Convert slice to JSON
		dataCategoriesJSON, err := json.Marshal(dataCategories)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to marshal data categories")
			return
		}
		dpaModel.DataCategories = datatypes.JSON(dataCategoriesJSON)
	}
	if dpaRequest.ProcessingLocation != nil {
		dpaModel.ProcessingLocation = *dpaRequest.ProcessingLocation
	}
	if dpaRequest.SubProcessingAllowed != nil {
		dpaModel.SubProcessingAllowed = *dpaRequest.SubProcessingAllowed
	}
	if len(dpaRequest.SecurityMeasures) > 0 {
		var securityMeasures []dpa.SecurityMeasure
		for _, s := range dpaRequest.SecurityMeasures {
			securityMeasures = append(securityMeasures, dpa.SecurityMeasure(s))
		}
		// Convert slice to JSON
		securityMeasuresJSON, err := json.Marshal(securityMeasures)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to marshal security measures")
			return
		}
		dpaModel.SecurityMeasures = datatypes.JSON(securityMeasuresJSON)
	}
	if dpaRequest.DataRetentionPeriod != nil {
		dpaModel.DataRetentionPeriod = *dpaRequest.DataRetentionPeriod
	}
	if len(dpaRequest.DataSubjectRights) > 0 {
		// Convert slice to JSON
		dataSubjectRightsJSON, err := json.Marshal(dpaRequest.DataSubjectRights)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to marshal data subject rights")
			return
		}
		dpaModel.DataSubjectRights = datatypes.JSON(dataSubjectRightsJSON)
	}
	if dpaRequest.BreachNotification != nil {
		dpaModel.BreachNotification = *dpaRequest.BreachNotification
	}
	if dpaRequest.AuditRights != nil {
		dpaModel.AuditRights = *dpaRequest.AuditRights
	}
	if dpaRequest.LiabilityCap != nil {
		dpaModel.LiabilityCap = *dpaRequest.LiabilityCap
	}
	if dpaRequest.InsuranceCoverage != nil {
		dpaModel.InsuranceCoverage = *dpaRequest.InsuranceCoverage
	}
	if dpaRequest.GoverningLaw != nil {
		dpaModel.GoverningLaw = *dpaRequest.GoverningLaw
	}
	if dpaRequest.SignatoryName != nil {
		dpaModel.SignatoryName = *dpaRequest.SignatoryName
	}
	if dpaRequest.SignatoryTitle != nil {
		dpaModel.SignatoryTitle = *dpaRequest.SignatoryTitle
	}
	if dpaRequest.Signature != nil {
		dpaModel.Signature = dpaRequest.Signature
	}
	if dpaRequest.SignedDate != nil {
		sd, err := time.Parse("2006-01-02", *dpaRequest.SignedDate)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid signed date format")
			return
		}
		dpaModel.SignedDate = &sd
	}
	if dpaRequest.Version != nil {
		dpaModel.Version = *dpaRequest.Version
	}

	dpaModel.UpdatedAt = time.Now()

	// Save to database using encrypted repository
	if err := h.EncryptedRepo.UpdateDPA(dpaModel); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update DPA")
		return
	}

	// Audit logging for DPA update
	if h.AuditService != nil {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims != nil {
			fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "dpa_updated", "updated", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"dpa_id":          dpaModel.ID.String(),
				"vendor_id":       dpaModel.VendorID.String(),
				"agreement_title": dpaRequest.AgreementTitle,
			})
		}
	}

	writeJSON(w, http.StatusOK, dpaModel)
}

// TerminateDPA terminates a Data Processing Agreement
func (h *DPAHandler) TerminateDPA(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dpaID, err := uuid.Parse(vars["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DPA ID")
		return
	}

	dpaModel, err := h.EncryptedRepo.GetDPAByID(dpaID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			writeError(w, http.StatusNotFound, "DPA not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to retrieve DPA")
		return
	}

	// Terminate the DPA
	dpaEntity := dpa.DataProcessingAgreement{
		Status: dpa.DPAStatus(dpaModel.Status),
	}

	if !dpaEntity.CanTerminate() {
		writeError(w, http.StatusBadRequest, "DPA cannot be terminated in its current status")
		return
	}

	dpaEntity.Terminate()
	dpaModel.Status = string(dpaEntity.Status)
	dpaModel.TerminationDate = dpaEntity.TerminationDate
	dpaModel.UpdatedAt = time.Now()

	// Save to database using encrypted repository
	if err := h.EncryptedRepo.UpdateDPA(dpaModel); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to terminate DPA")
		return
	}

	// Audit logging for DPA termination
	if h.AuditService != nil {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims != nil {
			fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "dpa_terminated", "terminated", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"dpa_id":          dpaModel.ID.String(),
				"vendor_id":       dpaModel.VendorID.String(),
				"agreement_title": dpaModel.AgreementTitle,
			})
		}
	}

	writeJSON(w, http.StatusOK, dpaModel)
}

// ListDPAs lists all Data Processing Agreements
func (h *DPAHandler) ListDPAs(w http.ResponseWriter, r *http.Request) {
	dpas, err := h.EncryptedRepo.ListDPAs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve DPAs")
		return
	}

	// Audit logging for DPA list access
	if h.AuditService != nil {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims != nil {
			fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "dpa_list_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"dpas_count": len(dpas),
			})
		}
	}

	writeJSON(w, http.StatusOK, dpas)
}

// GetDPAsByVendor retrieves all DPAs for a specific vendor
func (h *DPAHandler) GetDPAsByVendor(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	vendorID, err := uuid.Parse(vars["vendorId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid vendor ID")
		return
	}

	dpas, err := h.EncryptedRepo.GetDPAsByVendor(vendorID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve DPAs for vendor")
		return
	}

	// Audit logging for DPA vendor access
	if h.AuditService != nil {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims != nil {
			fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "dpa_vendor_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"vendor_id":  vendorID.String(),
				"dpas_count": len(dpas),
			})
		}
	}

	writeJSON(w, http.StatusOK, dpas)
}

// GetDPAsByTenant retrieves all DPAs for a specific tenant
func (h *DPAHandler) GetDPAsByTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID, err := uuid.Parse(vars["tenantId"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID")
		return
	}

	dpas, err := h.EncryptedRepo.GetDPAsByTenant(tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve DPAs for tenant")
		return
	}

	// Audit logging for DPA tenant access
	if h.AuditService != nil {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims != nil {
			fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
			go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "dpa_tenant_accessed", "accessed", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"tenant_id":  tenantID.String(),
				"dpas_count": len(dpas),
			})
		}
	}

	writeJSON(w, http.StatusOK, dpas)
}

// CreateComplianceCheck creates a new compliance check for a DPA
func (h *DPAHandler) CreateComplianceCheck(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dpaID, err := uuid.Parse(vars["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DPA ID")
		return
	}

	var complianceRequest struct {
		CheckedBy       string   `json:"checkedBy"`
		Compliant       bool     `json:"compliant"`
		Findings        []string `json:"findings,omitempty"`
		RemedialActions []string `json:"remedialActions,omitempty"`
		NextCheckDate   *string  `json:"nextCheckDate,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&complianceRequest); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var nextCheckDate *time.Time
	if complianceRequest.NextCheckDate != nil {
		ncd, err := time.Parse("2006-01-02", *complianceRequest.NextCheckDate)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid next check date format")
			return
		}
		nextCheckDate = &ncd
	}

	// Convert slices to JSON for compliance check
	findingsJSON, err := json.Marshal(complianceRequest.Findings)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to marshal findings")
		return
	}

	remedialActionsJSON, err := json.Marshal(complianceRequest.RemedialActions)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to marshal remedial actions")
		return
	}

	// Create the compliance check
	complianceCheck := models.DPAComplianceCheck{
		ID:              uuid.New(),
		DPAID:           dpaID,
		CheckDate:       time.Now(),
		CheckedBy:       complianceRequest.CheckedBy,
		Compliant:       complianceRequest.Compliant,
		Findings:        datatypes.JSON(findingsJSON),
		RemedialActions: datatypes.JSON(remedialActionsJSON),
		NextCheckDate:   nextCheckDate,
		CreatedAt:       time.Now(),
	}

	// Save to database
	if err := h.EncryptedRepo.CreateComplianceCheck(&complianceCheck); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create compliance check")
		return
	}

	// Audit logging for DPA compliance check creation
	if h.AuditService != nil {
		claims := middlewares.GetFiduciaryAuthClaims(r.Context())
		if claims != nil {
			fiduciaryID, _ := uuid.Parse(claims.FiduciaryID)
			tenantID, _ := uuid.Parse(claims.TenantID)
			go h.AuditService.Create(r.Context(), fiduciaryID, tenantID, uuid.Nil, "dpa_compliance_check_created", "created", claims.FiduciaryID, r.RemoteAddr, "", "", map[string]interface{}{
				"dpa_id":              dpaID.String(),
				"compliance_check_id": complianceCheck.ID.String(),
				"compliant":           complianceRequest.Compliant,
			})
		}
	}

	writeJSON(w, http.StatusCreated, complianceCheck)
}

// GetComplianceChecks retrieves all compliance checks for a DPA
func (h *DPAHandler) GetComplianceChecks(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dpaID, err := uuid.Parse(vars["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid DPA ID")
		return
	}

	complianceChecks, err := h.EncryptedRepo.GetComplianceChecks(dpaID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to retrieve compliance checks")
		return
	}

	writeJSON(w, http.StatusOK, complianceChecks)
}
