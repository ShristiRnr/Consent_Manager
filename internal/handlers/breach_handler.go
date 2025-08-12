package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"consultrnr/consent-manager/internal/breach"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// BreachHandler handles breach notification and reporting requests
type BreachHandler struct {
	DB                     *gorm.DB
	BreachReportingService *services.BreachReportingService
}

// NewBreachHandler creates a new breach handler
func NewBreachHandler(db *gorm.DB, breachReportingService *services.BreachReportingService) *BreachHandler {
	return &BreachHandler{
		DB:                     db,
		BreachReportingService: breachReportingService,
	}
}

// RegisterRoutes registers breach-related routes
func (h *BreachHandler) RegisterRoutes(r *mux.Router) {
	// Breach notification and reporting routes
	r.HandleFunc("/api/v1/breaches", h.CreateBreach).Methods("POST")
	r.HandleFunc("/api/v1/breaches/{id}", h.GetBreach).Methods("GET")
	r.HandleFunc("/api/v1/breaches/{id}", h.UpdateBreach).Methods("PUT")
	r.HandleFunc("/api/v1/breaches", h.ListBreaches).Methods("GET")
	r.HandleFunc("/api/v1/breaches/{id}/report-dpb", h.ReportBreachToDPB).Methods("POST")
	r.HandleFunc("/api/v1/breaches/process-pending", h.ProcessPendingBreachReports).Methods("POST")
}

// CreateBreach creates a new breach notification
func (h *BreachHandler) CreateBreach(w http.ResponseWriter, r *http.Request) {
	var breachRequest struct {
		TenantID           string   `json:"tenantId"`
		Description        string   `json:"description"`
		BreachDate         string   `json:"breachDate"`
		DetectionDate      string   `json:"detectionDate"`
		AffectedUsersCount int      `json:"affectedUsersCount"`
		Severity           string   `json:"severity"`
		BreachType         string   `json:"breachType"`
		RemedialActions    []string `json:"remedialActions,omitempty"`
		PreventiveMeasures []string `json:"preventiveMeasures,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&breachRequest); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}

	tenantID, err := uuid.Parse(breachRequest.TenantID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid tenant ID"})
		return
	}

	breachDate, err := time.Parse("2006-01-02", breachRequest.BreachDate)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid breach date format"})
		return
	}

	detectionDate, err := time.Parse("2006-01-02", breachRequest.DetectionDate)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid detection date format"})
		return
	}

	// Create the breach notification
	breachModel := models.BreachNotification{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Description:        breachRequest.Description,
		BreachDate:         breachDate,
		DetectionDate:      detectionDate,
		AffectedUsersCount: breachRequest.AffectedUsersCount,
		Severity:           breachRequest.Severity,
		BreachType:         breachRequest.BreachType,
		Status:             "Investigating",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	// Determine if DPB reporting is required
	breachEntity := &breach.BreachNotification{
		ID:                 breachModel.ID,
		TenantID:           breachModel.TenantID,
		Description:        breachModel.Description,
		BreachDate:         breachModel.BreachDate,
		DetectionDate:      breachModel.DetectionDate,
		AffectedUsersCount: breachModel.AffectedUsersCount,
		Severity:           breach.BreachSeverity(breachRequest.Severity),
		BreachType:         breach.BreachType(breachRequest.BreachType),
		CreatedAt:          breachModel.CreatedAt,
		UpdatedAt:          breachModel.UpdatedAt,
	}

	breachModel.RequiresDPBReporting = breachEntity.IsDPBReportable()

	// Save to database
	if err := h.DB.Create(&breachModel).Error; err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create breach notification"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(breachModel)
}

// GetBreach retrieves a specific breach notification
func (h *BreachHandler) GetBreach(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	breachID, err := uuid.Parse(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid breach ID"})
		return
	}

	var breachModel models.BreachNotification
	if err := h.DB.Where("id = ?", breachID).First(&breachModel).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Breach not found"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to retrieve breach"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(breachModel)
}

// UpdateBreach updates an existing breach notification
func (h *BreachHandler) UpdateBreach(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	breachID, err := uuid.Parse(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid breach ID"})
		return
	}

	var breachModel models.BreachNotification
	if err := h.DB.Where("id = ?", breachID).First(&breachModel).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Breach not found"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to retrieve breach"})
		return
	}

	var breachRequest struct {
		Description          *string  `json:"description,omitempty"`
		BreachDate           *string  `json:"breachDate,omitempty"`
		DetectionDate        *string  `json:"detectionDate,omitempty"`
		NotificationDate     *string  `json:"notificationDate,omitempty"`
		AffectedUsersCount   *int     `json:"affectedUsersCount,omitempty"`
		NotifiedUsersCount   *int     `json:"notifiedUsersCount,omitempty"`
		Severity             *string  `json:"severity,omitempty"`
		BreachType           *string  `json:"breachType,omitempty"`
		Status               *string  `json:"status,omitempty"`
		RemedialActions      []string `json:"remedialActions,omitempty"`
		PreventiveMeasures   []string `json:"preventiveMeasures,omitempty"`
		InvestigationSummary *string  `json:"investigationSummary,omitempty"`
		InvestigatedBy       *string  `json:"investigatedBy,omitempty"`
		InvestigationDate    *string  `json:"investigationDate,omitempty"`
		ComplianceStatus     *string  `json:"complianceStatus,omitempty"`
		ComplianceNotes      *string  `json:"complianceNotes,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&breachRequest); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request payload"})
		return
	}

	// Update fields if provided
	if breachRequest.Description != nil {
		breachModel.Description = *breachRequest.Description
	}
	if breachRequest.BreachDate != nil {
		bd, err := time.Parse("2006-01-02", *breachRequest.BreachDate)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid breach date format"})
			return
		}
		breachModel.BreachDate = bd
	}
	if breachRequest.DetectionDate != nil {
		ded, err := time.Parse("2006-01-02", *breachRequest.DetectionDate)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid detection date format"})
			return
		}
		breachModel.DetectionDate = ded
	}
	if breachRequest.NotificationDate != nil {
		nod, err := time.Parse("2006-01-02", *breachRequest.NotificationDate)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid notification date format"})
			return
		}
		breachModel.NotificationDate = &nod
	}
	if breachRequest.AffectedUsersCount != nil {
		breachModel.AffectedUsersCount = *breachRequest.AffectedUsersCount
	}
	if breachRequest.NotifiedUsersCount != nil {
		breachModel.NotifiedUsersCount = *breachRequest.NotifiedUsersCount
	}
	if breachRequest.Severity != nil {
		breachModel.Severity = *breachRequest.Severity
	}
	if breachRequest.BreachType != nil {
		breachModel.BreachType = *breachRequest.BreachType
	}
	if breachRequest.Status != nil {
		breachModel.Status = *breachRequest.Status
	}
	if len(breachRequest.RemedialActions) > 0 {
		// Convert slice to JSON
		remedialActionsJSON, err := json.Marshal(breachRequest.RemedialActions)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to marshal remedial actions"})
			return
		}
		breachModel.RemedialActions = datatypes.JSON(remedialActionsJSON)
	}
	if len(breachRequest.PreventiveMeasures) > 0 {
		// Convert slice to JSON
		preventiveMeasuresJSON, err := json.Marshal(breachRequest.PreventiveMeasures)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to marshal preventive measures"})
			return
		}
		breachModel.PreventiveMeasures = datatypes.JSON(preventiveMeasuresJSON)
	}
	if breachRequest.InvestigationSummary != nil {
		breachModel.InvestigationSummary = breachRequest.InvestigationSummary
	}
	if breachRequest.InvestigatedBy != nil {
		breachModel.InvestigatedBy = breachRequest.InvestigatedBy
	}
	if breachRequest.InvestigationDate != nil {
		id, err := time.Parse("2006-01-02", *breachRequest.InvestigationDate)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid investigation date format"})
			return
		}
		breachModel.InvestigationDate = &id
	}
	if breachRequest.ComplianceStatus != nil {
		breachModel.ComplianceStatus = *breachRequest.ComplianceStatus
	}
	if breachRequest.ComplianceNotes != nil {
		breachModel.ComplianceNotes = breachRequest.ComplianceNotes
	}

	breachModel.UpdatedAt = time.Now()

	// Save to database
	if err := h.DB.Save(&breachModel).Error; err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update breach"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(breachModel)
}

// ListBreaches lists all breach notifications
func (h *BreachHandler) ListBreaches(w http.ResponseWriter, r *http.Request) {
	var breaches []models.BreachNotification
	if err := h.DB.Find(&breaches).Error; err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to retrieve breaches"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(breaches)
}

// ReportBreachToDPB manually triggers reporting of a breach to the Data Protection Board
func (h *BreachHandler) ReportBreachToDPB(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	breachID, err := uuid.Parse(vars["id"])
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid breach ID"})
		return
	}

	// Trigger the breach reporting service
	if err := h.BreachReportingService.CheckAndReportBreach(r.Context(), breachID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to report breach to DPB: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Breach reported to DPB successfully"})
}

// ProcessPendingBreachReports processes all pending breach reports that need to be sent to the DPB
func (h *BreachHandler) ProcessPendingBreachReports(w http.ResponseWriter, r *http.Request) {
	if err := h.BreachReportingService.ProcessPendingBreachReports(r.Context()); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to process pending breach reports: " + err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Pending breach reports processed successfully"})
}
