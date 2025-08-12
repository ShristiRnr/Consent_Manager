package breach

import (
	"time"

	"github.com/google/uuid"
)

// DPBReportStatus represents the status of a report to the Data Protection Board
type DPBReportStatus string

const (
	DPBReportStatusPending    DPBReportStatus = "pending"
	DPBReportStatusSubmitted  DPBReportStatus = "submitted"
	DPBReportStatusConfirmed  DPBReportStatus = "confirmed"
	DPBReportStatusFailed     DPBReportStatus = "failed"
)

// BreachSeverity represents the severity level of a data breach
type BreachSeverity string

const (
	BreachSeverityLow      BreachSeverity = "low"
	BreachSeverityMedium   BreachSeverity = "medium"
	BreachSeverityHigh     BreachSeverity = "high"
	BreachSeverityCritical BreachSeverity = "critical"
)

// BreachType represents the type of data breach
type BreachType string

const (
	BreachTypeUnauthorizedAccess BreachType = "unauthorized_access"
	BreachTypeDataTheft          BreachType = "data_theft"
	BreachTypeLostDevice         BreachType = "lost_device"
	BreachTypeSystemVulnerability BreachType = "system_vulnerability"
	BreachTypeInsiderThreat      BreachType = "insider_threat"
	BreachTypePhysicalTheft      BreachType = "physical_theft"
	BreachTypeMalwareAttack      BreachType = "malware_attack"
	BreachTypeSocialEngineering  BreachType = "social_engineering"
)

// DPBBreachReport represents a report to the Data Protection Board as required by DPDP
type DPBBreachReport struct {
	ID                   uuid.UUID       `json:"id"`
	BreachID             uuid.UUID       `json:"breachId"`
	TenantID             uuid.UUID       `json:"tenantId"`
	ReportReference      string          `json:"reportReference"`
	Status               DPBReportStatus `json:"status"`
	SubmissionDate       *time.Time      `json:"submissionDate,omitempty"`
	ConfirmationDate     *time.Time      `json:"confirmationDate,omitempty"`
	LastError            *string         `json:"lastError,omitempty"`
	RetryCount           int             `json:"retryCount"`
	NextRetryDate        *time.Time      `json:"nextRetryDate,omitempty"`
	CreatedAt            time.Time       `json:"createdAt"`
	UpdatedAt            time.Time       `json:"updatedAt"`
}

// BreachNotification represents an enhanced breach notification with DPDP requirements
type BreachNotification struct {
	ID                   uuid.UUID     `json:"id"`
	TenantID             uuid.UUID     `json:"tenantId"`
	Description          string        `json:"description"`
	BreachDate           time.Time     `json:"breachDate"`
	DetectionDate        time.Time     `json:"detectionDate"`
	NotificationDate     *time.Time    `json:"notificationDate,omitempty"`
	AffectedUsersCount   int           `json:"affectedUsersCount"`
	NotifiedUsersCount   int           `json:"notifiedUsersCount"`
	Severity             BreachSeverity `json:"severity"`
	BreachType           BreachType    `json:"breachType"`
	// DPDP-specific fields
	RequiresDPBReporting bool          `json:"requiresDPBReporting"`
	DPBReported          bool          `json:"dpbReported"`
	DPBReportedDate      *time.Time    `json:"dpbReportedDate,omitempty"`
	DPBReportReference   *string       `json:"dpbReportReference,omitempty"`
	// Remediation details
	RemedialActions      []string      `json:"remedialActions,omitempty"`
	PreventiveMeasures   []string      `json:"preventiveMeasures,omitempty"`
	// Investigation details
	InvestigationSummary *string       `json:"investigationSummary,omitempty"`
	InvestigatedBy       *string       `json:"investigatedBy,omitempty"`
	InvestigationDate    *time.Time    `json:"investigationDate,omitempty"`
	// Compliance details
	ComplianceStatus     string        `json:"complianceStatus"`
	ComplianceNotes      *string       `json:"complianceNotes,omitempty"`
	CreatedAt            time.Time     `json:"createdAt"`
	UpdatedAt            time.Time     `json:"updatedAt"`
}

// IsDPBReportable checks if a breach requires reporting to the Data Protection Board
func (bn *BreachNotification) IsDPBReportable() bool {
	// According to DPDP, certain breaches must be reported to the DPB
	// This is a simplified implementation - in practice, this would be more complex
	
	// Report if it's a high or critical severity breach
	if bn.Severity == BreachSeverityHigh || bn.Severity == BreachSeverityCritical {
		return true
	}
	
	// Report if it affects a large number of users
	if bn.AffectedUsersCount >= 1000 {
		return true
	}
	
	// Report certain types of breaches regardless of severity
	reportableTypes := []BreachType{
		BreachTypeDataTheft,
		BreachTypePhysicalTheft,
		BreachTypeInsiderThreat,
	}
	
	for _, t := range reportableTypes {
		if bn.BreachType == t {
			return true
		}
	}
	
	return false
}

// GenerateDPBReport generates the content for a DPDP breach report
func (bn *BreachNotification) GenerateDPBReport() map[string]interface{} {
	return map[string]interface{}{
		"breachId":             bn.ID.String(),
		"tenantId":             bn.TenantID.String(),
		"description":          bn.Description,
		"breachDate":           bn.BreachDate,
		"detectionDate":        bn.DetectionDate,
		"notificationDate":     bn.NotificationDate,
		"affectedUsersCount":   bn.AffectedUsersCount,
		"severity":             string(bn.Severity),
		"breachType":           string(bn.BreachType),
		"remedialActions":      bn.RemedialActions,
		"preventiveMeasures":   bn.PreventiveMeasures,
		"investigationSummary": bn.InvestigationSummary,
		"investigatedBy":       bn.InvestigatedBy,
		"investigationDate":    bn.InvestigationDate,
	}
}

// MarkAsReportedToDPB marks the breach as reported to the Data Protection Board
func (bn *BreachNotification) MarkAsReportedToDPB(reportReference string) {
	bn.DPBReported = true
	bn.DPBReportedDate = &bn.UpdatedAt
	bn.DPBReportReference = &reportReference
}
