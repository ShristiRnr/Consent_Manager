package models

import (
	"consultrnr/consent-manager/internal/dto"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// -------------------------------
// Admin and Organizational Models
// -------------------------------
type FiduciaryUser struct {
	ID                  uuid.UUID `gorm:"type:uuid;primaryKey"`
	TenantID            uuid.UUID `gorm:"type:uuid;index"`
	Email               string    `gorm:"type:text;uniqueIndex"`
	Phone               string    `gorm:"type:text;uniqueIndex"`
	Name                string    `gorm:"type:text"`
	PasswordHash        string    `gorm:"type:text"`
	Role                string    `gorm:"type:varchar(20);default:'viewer'"` // E.g., admin, dpo, viewer
	IsVerified          bool      `gorm:"default:false"`
	VerificationToken   string    `gorm:"type:text;index"`
	VerificationExpiry  time.Time
	PasswordResetToken  string `gorm:"type:text"`
	PasswordResetExpiry time.Time
	CreatedAt           time.Time `gorm:"autoCreateTime"`
	LastSeen            time.Time `gorm:"autoUpdateTime"`

	// Permissions
	CanManageConsent      bool `gorm:"default:false"`
	CanManageGrievance    bool `gorm:"default:false"`
	CanManagePurposes     bool `gorm:"default:false"`
	CanManageAuditLogs    bool `gorm:"default:false"`
	CanManageConsentForms bool `gorm:"default:false"`
}

// DataPrincipal represents the end-user (the data subject).
type DataPrincipal struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey"`
	TenantID           uuid.UUID `gorm:"type:uuid;index"` // Link to the DF's tenant
	ExternalID         string    `gorm:"type:text;index"` // ID from the fiduciary's system
	Email              string    `gorm:"type:text;index"`
	Phone              string    `gorm:"type:text;index"`
	FirstName          string    `gorm:"type:text"`
	LastName           string    `gorm:"type:text"`
	Age                int       `gorm:"type:int"`
	Location           string    `gorm:"type:text"`
	IsVerified         bool      `gorm:"default:false"`
	VerificationToken  string    `gorm:"type:text;index"`
	VerificationExpiry time.Time

	// Guardian-related fields for minors
	GuardianEmail              string `gorm:"type:text;index"`
	IsGuardianVerified         bool   `gorm:"default:false"`
	GuardianVerificationToken  string `gorm:"type:text;index"`
	GuardianVerificationExpiry time.Time

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

// EncryptedDataPrincipal represents a DataPrincipal with encrypted sensitive fields
type EncryptedDataPrincipal struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey"`
	TenantID           uuid.UUID `gorm:"type:uuid;index"` // Link to the DF's tenant
	ExternalID         string    `gorm:"type:text;index"` // ID from the fiduciary's system
	Email              string    `gorm:"type:text;index"`
	Phone              string    `gorm:"type:text;index"`
	FirstName          string    `gorm:"type:text"`
	LastName           string    `gorm:"type:text"`
	Age                int       `gorm:"type:int"`
	Location           string    `gorm:"type:text"`
	IsVerified         bool      `gorm:"default:false"`
	VerificationToken  string    `gorm:"type:text;index"`
	VerificationExpiry time.Time

	// Guardian-related fields for minors
	GuardianEmail              string `gorm:"type:text;index"`
	IsGuardianVerified         bool   `gorm:"default:false"`
	GuardianVerificationToken  string `gorm:"type:text;index"`
	GuardianVerificationExpiry time.Time

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

type UserTenantLink struct {
	ID             uuid.UUID `gorm:"primaryKey"`
	UserID         uuid.UUID `gorm:"type:uuid;index"`
	TenantID       uuid.UUID `gorm:"type:uuid;index"`
	TenantName     string
	FirstGrantedAt time.Time
	LastUpdatedAt  time.Time
}

// -------------------------------
// Consent & Purpose Models
// -------------------------------
type Purpose struct {
	ID                uuid.UUID `gorm:"primaryKey"`
	Name              string
	Description       string
	Required          bool
	Active            bool
	ReviewCycleMonths int
	LegalBasis        string
	Version           string
	Language          string
	TenantID          uuid.UUID      `gorm:"index"`
	Vendors           pq.StringArray `gorm:"type:text[]" json:"vendors"`
	IsThirdParty      bool           `gorm:"default:false"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
	LastUsedAt        *time.Time
	TotalGranted      int
	TotalRevoked      int
}

func (Purpose) TableName() string {
	return "purposes"
}

type PurposeStatus struct {
	Name     string `json:"name"`
	Status   bool   `json:"status"`
	Version  string `json:"version"`
	Language string `json:"language"`
}

type PendingConsent struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey"`
	MinorUserID    uuid.UUID  `gorm:"type:uuid"`
	GuardianUserID *uuid.UUID `gorm:"type:uuid;default:null"` // dashboard flow, null for DigiLocker
	Updates        []byte     `gorm:"type:jsonb"`             // json.Marshal([]ConsentUpdateRequest)
	Status         string     `gorm:"type:varchar(32)"`
	Token          string     `gorm:"type:text"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ConsentHistory struct {
	ID             uuid.UUID `gorm:"primaryKey"`
	ConsentID      uuid.UUID `gorm:"index"`
	UserID         uuid.UUID `gorm:"index"`
	TenantID       uuid.UUID `gorm:"index"`
	Action         string
	Purposes       datatypes.JSON `gorm:"type:jsonb" json:"purposes"`
	ChangedBy      string
	PolicySnapshot datatypes.JSON `gorm:"type:jsonb"`
	Timestamp      time.Time      `gorm:"autoCreateTime"`
	ReviewTokenID  *uuid.UUID     `gorm:"index"`
}

func (ConsentHistory) TableName() string {
	return "consent_histories"
}

type ReviewToken struct {
	ID        uuid.UUID `gorm:"primaryKey"`
	Token     string    `gorm:"uniqueIndex"`
	UserID    uuid.UUID `gorm:"index"`
	TenantID  uuid.UUID `gorm:"index"`
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Consent struct {
	ID             uuid.UUID           `gorm:"primaryKey"`
	UserID         uuid.UUID           `gorm:"index"`
	Purposes       dto.ConsentPurposes `gorm:"type:jsonb" json:"purposes"`
	PolicySnapshot datatypes.JSON      `gorm:"type:jsonb" json:"policy_snapshot"`
	Signature      string
	GeoRegion      string
	Jurisdiction   string
	TenantID       uuid.UUID `gorm:"index"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type EncryptedConsent struct {
	ID             uuid.UUID      `gorm:"primaryKey"`
	UserID         uuid.UUID      `gorm:"index"`
	Purposes       datatypes.JSON `gorm:"type:jsonb" json:"purposes"`
	PolicySnapshot datatypes.JSON `gorm:"type:jsonb" json:"policy_snapshot"`
	Signature      string
	GeoRegion      string
	Jurisdiction   string
	TenantID       uuid.UUID `gorm:"index"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type UserConsent struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID        uuid.UUID `gorm:"type:uuid;index"`
	PurposeID     uuid.UUID `gorm:"type:uuid;index"`
	TenantID      uuid.UUID `gorm:"type:uuid;index"`
	ConsentFormID uuid.UUID `gorm:"type:uuid;index"`
	Status        bool      // true for granted, false for withdrawn
	ExpiresAt     *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type ConsentLink struct {
	ID              uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Link            string    `gorm:"type:text;not null;unique"`
	TenantID        uuid.UUID `gorm:"type:uuid;not null;index"`
	Name            string
	SubmissionCount int    `gorm:"default:0"`
	Metadata        []byte `gorm:"type:jsonb;default:null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (ConsentLink) TableName() string {
	return "consent_links"
}

// -------------------------------
// Privacy & Compliance Models
// -------------------------------
type DSRRequest struct {
	ID             uuid.UUID `gorm:"primaryKey"`
	UserID         uuid.UUID `gorm:"index"`
	TenantID       uuid.UUID `gorm:"index"`
	Type           string    `gorm:"type:varchar(20)"`
	Status         string    `gorm:"type:varchar(20)"`
	RequestedAt    time.Time
	ProcessedAt    *time.Time
	ResolutionNote string
	ResolvedAt     gorm.DeletedAt `gorm:"index"`
	CreatedAt      time.Time      `gorm:"autoCreateTime"`
	UpdatedAt      time.Time      `gorm:"autoUpdateTime"`
}

type AuditLog struct {
	LogID         uuid.UUID `gorm:"primaryKey"`
	UserID        uuid.UUID `gorm:"index"`
	TenantID      uuid.UUID `gorm:"index"`
	PurposeID     uuid.UUID `gorm:"index"`
	ActionType    string
	Timestamp     time.Time `gorm:"autoCreateTime"`
	ConsentStatus string
	Initiator     string
	SourceIP      string
	GeoRegion     string
	Jurisdiction  string
	AuditHash     string
	PreviousHash  string
	Details       datatypes.JSON `gorm:"type:jsonb"`
}

type NotificationPreferences struct {
	UserID                     uuid.UUID `gorm:"primaryKey"`
	OnNewGrievance             bool      `gorm:"default:true"`
	OnGrievanceUpdate          bool      `gorm:"default:true"`
	OnConsentUpdate            bool      `gorm:"default:true"`
	OnNewConsentRequest        bool      `gorm:"default:true"`
	OnDataSubjectRequest       bool      `gorm:"default:true"`
	OnDataSubjectRequestUpdate bool      `gorm:"default:true"`
}

// -------------------------------
// Engagement & Notification Models
// -------------------------------
type Grievance struct {
	ID                   uuid.UUID  `gorm:"primaryKey" json:"id"`
	UserID               uuid.UUID  `gorm:"index" json:"userId"`
	TenantID             uuid.UUID  `gorm:"index" json:"tenantId"`
	GrievanceType        string     `json:"grievanceType"`
	GrievanceSubject     string     `json:"grievanceSubject"`
	GrievanceDescription string     `json:"grievanceDescription"`
	Status               string     `json:"status"` // e.g., open, in_progress, resolved, closed
	AssignedTo           *uuid.UUID `gorm:"index" json:"assignedTo,omitempty"`
	Category             string     `json:"category"` // e.g., billing, technical, general
	Priority             string     `json:"priority"` // e.g., low, medium, high, urgent
	CreatedAt            time.Time  `json:"createdAt"`
	UpdatedAt            time.Time  `json:"updatedAt"`
}

// ===================== GrievanceComment (Chat) =====================
type GrievanceComment struct {
	ID          uuid.UUID  `gorm:"primaryKey" json:"id"`
	GrievanceID uuid.UUID  `gorm:"index" json:"grievanceId"`
	UserID      uuid.UUID  `gorm:"index" json:"userId"`
	AdminId     *uuid.UUID `gorm:"index" json:"adminId,omitempty"`
	Comment     string     `json:"comment"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// ===================== Notification =====================
type Notification struct {
	ID        uuid.UUID `gorm:"primaryKey" json:"id"`
	UserID    uuid.UUID `gorm:"index" json:"userId"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Icon      string    `json:"icon"`
	Link      string    `json:"link,omitempty"`
	Unread    bool      `gorm:"index" json:"unread"`
	CreatedAt time.Time `json:"createdAt"`
}

// -------------------------------
// API & Webhook Infrastructure
// -------------------------------
type APIKey struct {
	KeyID          uuid.UUID `gorm:"primaryKey"`
	TenantID       uuid.UUID `gorm:"index"`
	UserID         uuid.UUID `gorm:"index"`
	Label          string
	HashedKey      string
	Scopes         datatypes.JSON `gorm:"type:jsonb" json:"scopes"`
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	Revoked        bool
	RevokedAt      *time.Time
	ExpiresAt      *time.Time
	WhitelistedIPs datatypes.JSON `gorm:"type:jsonb" json:"whitelisted_ips"`
}

// -------------------------------
// Tenant Infrastructure
// -------------------------------
type Tenant struct {
	TenantID              uuid.UUID `gorm:"primaryKey"`
	Name                  string
	Cluster               string
	Domain                string
	Industry              string
	CompanySize           string
	Config                datatypes.JSON
	ReviewFrequencyMonths int `gorm:"default:6"`
	CreatedAt             time.Time
}

// -------------------------------
// Data Processor
// -------------------------------
type Vendor struct {
	VendorID uuid.UUID `gorm:"primaryKey" json:"id"`
	Company  string
	Email    string `gorm:"type:text;uniqueIndex"`
	Address  string
	// DPA-related fields
	DPAAgreementID         *uuid.UUID `gorm:"type:uuid" json:"dpaAgreementId,omitempty"`
	ProcessingLocation     string     `gorm:"type:text" json:"processingLocation,omitempty"`
	SecurityCertifications string     `gorm:"type:text" json:"securityCertifications,omitempty"`
	LastComplianceCheck    *time.Time `gorm:"type:timestamp" json:"lastComplianceCheck,omitempty"`
	ComplianceStatus       string     `gorm:"type:text" json:"complianceStatus,omitempty"`
	CreatedAt              time.Time  `gorm:"autoCreateTime" json:"createdAt"`
	UpdatedAt              time.Time  `gorm:"autoUpdateTime" json:"updatedAt"`
}

// -------------------------------
// Consent Form Models
// -------------------------------
type ConsentForm struct {
	ID                      uuid.UUID            `gorm:"type:uuid;primaryKey"`
	TenantID                uuid.UUID            `gorm:"type:uuid;index"`
	Name                    string               `gorm:"type:text"`
	Title                   string               `gorm:"type:text"`
	Description             string               `gorm:"type:text"`
	DataCollectionAndUsage  string               `gorm:"type:text"`
	DataSharingAndTransfers string               `gorm:"type:text"`
	DataRetentionPeriod     string               `gorm:"type:text"`
	UserRightsSummary       string               `gorm:"type:text"`
	TermsAndConditions      string               `gorm:"type:text"`
	PrivacyPolicy           string               `gorm:"type:text"`
	Purposes                []ConsentFormPurpose `gorm:"foreignKey:ConsentFormID"`
	Published               bool                 `gorm:"default:false"`
	CreatedAt               time.Time            `gorm:"autoCreateTime"`
	UpdatedAt               time.Time            `gorm:"autoUpdateTime"`
}

type ConsentFormPurpose struct {
	ID            uuid.UUID      `gorm:"type:uuid;primaryKey"`
	ConsentFormID uuid.UUID      `gorm:"type:uuid;index"`
	PurposeID     uuid.UUID      `gorm:"type:uuid;index"`
	Purpose       Purpose        `gorm:"foreignKey:PurposeID"`
	DataObjects   pq.StringArray `gorm:"type:text[]"`
	VendorIDs     pq.StringArray `gorm:"type:text[]"`
	ExpiryInDays  int
}

// -------------------------------
// OAuth Client Models
// -------------------------------

type OAuthClient struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey"`
	TenantID     uuid.UUID      `gorm:"type:uuid;index"`
	ClientID     string         `gorm:"type:varchar(255);uniqueIndex"`
	ClientSecret string         `gorm:"type:text"` // This will be a hash
	AppName      string         `gorm:"type:text"`
	Scopes       pq.StringArray `gorm:"type:text[]"`
	Revoked      bool           `gorm:"default:false"`
	CreatedAt    time.Time      `gorm:"autoCreateTime"`
	UpdatedAt    time.Time      `gorm:"autoUpdateTime"`
}

// -------------------------------
// Breach Notification Models
// -------------------------------

type BreachNotification struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey"`
	TenantID           uuid.UUID `gorm:"type:uuid;index"`
	Description        string    `gorm:"type:text"`
	BreachDate         time.Time
	DetectionDate      time.Time
	NotificationDate   *time.Time
	AffectedUsersCount int
	NotifiedUsersCount int
	Severity           string `gorm:"type:varchar(20)"` // low, medium, high, critical
	BreachType         string `gorm:"type:varchar(50)"` // unauthorized_access, data_theft, etc.
	Status             string `gorm:"type:varchar(50)"` // e.g., Investigating, Notifying, Resolved
	// DPDP-specific fields
	RequiresDPBReporting bool `gorm:"default:false"`
	DPBReported          bool `gorm:"default:false"`
	DPBReportedDate      *time.Time
	DPBReportReference   *string `gorm:"type:text"`
	// Remediation details
	RemedialActions    datatypes.JSON `gorm:"type:jsonb"`
	PreventiveMeasures datatypes.JSON `gorm:"type:jsonb"`
	// Investigation details
	InvestigationSummary *string `gorm:"type:text"`
	InvestigatedBy       *string `gorm:"type:text"`
	InvestigationDate    *time.Time
	// Compliance details
	ComplianceStatus string    `gorm:"type:varchar(50)"`
	ComplianceNotes  *string   `gorm:"type:text"`
	CreatedAt        time.Time `gorm:"autoCreateTime"`
	UpdatedAt        time.Time `gorm:"autoUpdateTime"`
}

type EncryptedBreachNotification struct {
	ID                 uuid.UUID `gorm:"type:uuid;primaryKey"`
	TenantID           uuid.UUID `gorm:"type:uuid;index"`
	Description        string    `gorm:"type:text"`
	BreachDate         time.Time
	DetectionDate      time.Time
	NotificationDate   *time.Time
	AffectedUsersCount int
	NotifiedUsersCount int
	Severity           string `gorm:"type:varchar(20)"` // low, medium, high, critical
	BreachType         string `gorm:"type:varchar(50)"` // unauthorized_access, data_theft, etc.
	Status             string `gorm:"type:varchar(50)"` // e.g., Investigating, Notifying, Resolved
	// DPDP-specific fields
	RequiresDPBReporting bool `gorm:"default:false"`
	DPBReported          bool `gorm:"default:false"`
	DPBReportedDate      *time.Time
	DPBReportReference   *string `gorm:"type:text"`
	// Remediation details
	RemedialActions    datatypes.JSON `gorm:"type:jsonb"`
	PreventiveMeasures datatypes.JSON `gorm:"type:jsonb"`
	// Investigation details
	InvestigationSummary *string `gorm:"type:text"`
	InvestigatedBy       *string `gorm:"type:text"`
	InvestigationDate    *time.Time
	// Compliance details
	ComplianceStatus string    `gorm:"type:varchar(50)"`
	ComplianceNotes  *string   `gorm:"type:text"`
	CreatedAt        time.Time `gorm:"autoCreateTime"`
	UpdatedAt        time.Time `gorm:"autoUpdateTime"`
}

func (b BreachNotification) BreachSeverity(severity string) string {
	switch severity {
	case "low":
		return "Low"
	case "medium":
		return "Medium"
	case "high":
		return "High"
	case "critical":
		return "Critical"
	default:
		return "Unknown"
	}
}
