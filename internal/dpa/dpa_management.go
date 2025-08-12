package dpa

import (
	"time"

	"github.com/google/uuid"
)

// DPAStatus represents the status of a Data Processing Agreement
type DPAStatus string

const (
	DPAStatusPending    DPAStatus = "pending"
	DPAStatusActive     DPAStatus = "active"
	DPAStatusExpired    DPAStatus = "expired"
	DPAStatusTerminated DPAStatus = "terminated"
	DPAStatusRevoked    DPAStatus = "revoked"
)

// ProcessingPurpose represents the purpose of data processing under a DPA
type ProcessingPurpose string

const (
	PurposeDataCollection    ProcessingPurpose = "data_collection"
	PurposeDataStorage       ProcessingPurpose = "data_storage"
	PurposeDataProcessing    ProcessingPurpose = "data_processing"
	PurposeDataTransfer      ProcessingPurpose = "data_transfer"
	PurposeDataDeletion      ProcessingPurpose = "data_deletion"
	PurposeDataAnalysis      ProcessingPurpose = "data_analysis"
	PurposeDataSharing       ProcessingPurpose = "data_sharing"
	PurposeMarketing         ProcessingPurpose = "marketing"
	PurposePersonalization   ProcessingPurpose = "personalization"
	PurposeResearch          ProcessingPurpose = "research"
)

// DataCategory represents categories of personal data processed under a DPA
type DataCategory string

const (
	CategoryPersonalInfo     DataCategory = "personal_info"
	CategoryContactInfo      DataCategory = "contact_info"
	CategoryFinancialInfo    DataCategory = "financial_info"
	CategoryHealthInfo       DataCategory = "health_info"
	CategoryBiometricInfo    DataCategory = "biometric_info"
	CategoryOnlineActivity   DataCategory = "online_activity"
	CategoryLocationData     DataCategory = "location_data"
	CategoryDeviceInfo       DataCategory = "device_info"
	CategoryContentData      DataCategory = "content_data"
	CategoryMetadata         DataCategory = "metadata"
)

// SecurityMeasure represents security measures implemented for data processing
type SecurityMeasure string

const (
	MeasureEncryption        SecurityMeasure = "encryption"
	MeasureAccessControl     SecurityMeasure = "access_control"
	MeasureDataMasking       SecurityMeasure = "data_masking"
	MeasureAuditLogging      SecurityMeasure = "audit_logging"
	MeasureBackupRecovery    SecurityMeasure = "backup_recovery"
	MeasureIntrusionDetection SecurityMeasure = "intrusion_detection"
	MeasureVulnerabilityMgmt SecurityMeasure = "vulnerability_management"
)

// DataProcessingAgreement represents a Data Processing Agreement as required by DPDP
type DataProcessingAgreement struct {
	ID                   uuid.UUID         `json:"id"`
	TenantID             uuid.UUID         `json:"tenantId"`
	VendorID             uuid.UUID         `json:"vendorId"`
	AgreementTitle       string            `json:"agreementTitle"`
	AgreementNumber      string            `json:"agreementNumber"`
	Status               DPAStatus         `json:"status"`
	EffectiveDate        time.Time         `json:"effectiveDate"`
	ExpiryDate           *time.Time        `json:"expiryDate,omitempty"`
	TerminationDate      *time.Time        `json:"terminationDate,omitempty"`
	ProcessingPurposes   []ProcessingPurpose `json:"processingPurposes"`
	DataCategories       []DataCategory    `json:"dataCategories"`
	ProcessingLocation   string            `json:"processingLocation"` // Country/region where processing occurs
	SubProcessingAllowed bool              `json:"subProcessingAllowed"`
	SecurityMeasures     []SecurityMeasure `json:"securityMeasures"`
	DataRetentionPeriod  string            `json:"dataRetentionPeriod"`
	DataSubjectRights    []string          `json:"dataSubjectRights"` // Rights provided to data subjects
	BreachNotification   bool              `json:"breachNotification"` // Obligation to notify of breaches
	AuditRights          bool              `json:"auditRights"`       // Right to audit compliance
	LiabilityCap         string            `json:"liabilityCap"`      // Liability limitations
	InsuranceCoverage    string            `json:"insuranceCoverage"` // Insurance requirements
	GoverningLaw         string            `json:"governingLaw"`      // Governing law and jurisdiction
	SignatoryName        string            `json:"signatoryName"`
	SignatoryTitle       string            `json:"signatoryTitle"`
	Signature            *string           `json:"signature,omitempty"`
	SignedDate           *time.Time        `json:"signedDate,omitempty"`
	CreatedAt            time.Time         `json:"createdAt"`
	UpdatedAt            time.Time         `json:"updatedAt"`
	Version              string            `json:"version"`
	PreviousVersionID    *uuid.UUID        `json:"previousVersionId,omitempty"`
}

// DPAComplianceCheck represents a compliance check for a DPA
type DPAComplianceCheck struct {
	ID              uuid.UUID     `json:"id"`
	DPAID           uuid.UUID     `json:"dpaId"`
	CheckDate       time.Time     `json:"checkDate"`
	CheckedBy       string        `json:"checkedBy"` // User ID or system
	Compliant       bool          `json:"compliant"`
	Findings        []string      `json:"findings,omitempty"`
	RemedialActions []string      `json:"remedialActions,omitempty"`
	NextCheckDate   *time.Time    `json:"nextCheckDate,omitempty"`
	CreatedAt       time.Time     `json:"createdAt"`
}

// DPAAudit represents an audit record for DPA operations
type DPAAudit struct {
	ID              uuid.UUID   `json:"id"`
	DPAID           uuid.UUID   `json:"dpaId"`
	Action          string      `json:"action"` // created, updated, terminated, etc.
	ActionPerformedBy string    `json:"actionPerformedBy"`
	ActionPerformedAt time.Time `json:"actionPerformedAt"`
	Details         string      `json:"details,omitempty"`
	IPAddress       string      `json:"ipAddress,omitempty"`
	UserAgent       string      `json:"userAgent,omitempty"`
}

// Validate checks if the DPA meets basic requirements
func (dpa *DataProcessingAgreement) Validate() []string {
	var violations []string
	
	// Check if agreement has a title
	if dpa.AgreementTitle == "" {
		violations = append(violations, "DPA must have a title")
	}
	
	// Check if agreement has a vendor
	if dpa.VendorID == uuid.Nil {
		violations = append(violations, "DPA must specify a vendor")
	}
	
	// Check if agreement has processing purposes
	if len(dpa.ProcessingPurposes) == 0 {
		violations = append(violations, "DPA must specify processing purposes")
	}
	
	// Check if agreement has data categories
	if len(dpa.DataCategories) == 0 {
		violations = append(violations, "DPA must specify data categories")
	}
	
	// Check if agreement has security measures
	if len(dpa.SecurityMeasures) == 0 {
		violations = append(violations, "DPA must specify security measures")
	}
	
	// Check if agreement has a data retention period
	if dpa.DataRetentionPeriod == "" {
		violations = append(violations, "DPA must specify a data retention period")
	}
	
	// Check if agreement has data subject rights
	if len(dpa.DataSubjectRights) == 0 {
		violations = append(violations, "DPA must specify data subject rights")
	}
	
	// Check if agreement has governing law
	if dpa.GoverningLaw == "" {
		violations = append(violations, "DPA must specify governing law")
	}
	
	// Check if agreement has a signatory
	if dpa.SignatoryName == "" || dpa.SignatoryTitle == "" {
		violations = append(violations, "DPA must have a signatory with name and title")
	}
	
	return violations
}

// IsActive checks if the DPA is currently active
func (dpa *DataProcessingAgreement) IsActive() bool {
	if dpa.ExpiryDate != nil {
		return dpa.Status == DPAStatusActive && time.Now().Before(*dpa.ExpiryDate)
	}
	return dpa.Status == DPAStatusActive
}

// IsExpired checks if the DPA has expired
func (dpa *DataProcessingAgreement) IsExpired() bool {
	if dpa.ExpiryDate == nil {
		return false
	}
	return time.Now().After(*dpa.ExpiryDate)
}

// CanTerminate checks if the DPA can be terminated
func (dpa *DataProcessingAgreement) CanTerminate() bool {
	return dpa.Status == DPAStatusActive || dpa.Status == DPAStatusPending
}

// Terminate marks the DPA as terminated
func (dpa *DataProcessingAgreement) Terminate() {
	if dpa.CanTerminate() {
		dpa.Status = DPAStatusTerminated
		terminationDate := time.Now()
		dpa.TerminationDate = &terminationDate
		dpa.UpdatedAt = terminationDate
	}
}
