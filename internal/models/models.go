package models

import (
	"consultrnr/consent-manager/internal/dto"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/datatypes"
)

// -------------------------------
// Admin and Organizational Models
// -------------------------------
type AdminLoginIndex struct {
	AdminID  uuid.UUID `gorm:"primaryKey"`
	TenantID uuid.UUID `gorm:"index"`
	Email    string    `gorm:"index"`
}

type AdminUser struct {
	AdminID             uuid.UUID `gorm:"type:uuid;primaryKey"`
	TenantID            uuid.UUID `gorm:"type:uuid;index"`
	ExternalID          string
	Role                string `gorm:"type:varchar(20);default:'admin'"`
	Identified          bool
	Email               string    `gorm:"type:text;index"`
	Phone               string    `gorm:"type:text"`
	Name                string    `gorm:"type:text"`
	PasswordHash        string    `gorm:"type:text"` // bcrypt hash
	GeoRegion           string    `gorm:"type:text"`
	Jurisdiction        string    `gorm:"type:text"`
	CreatedAt           time.Time `gorm:"autoCreateTime"`
	LastSeen            time.Time `gorm:"autoUpdateTime"`
	PasswordResetToken  string    `gorm:"type:text"`
	PasswordResetExpiry time.Time
}

type TenantUser struct {
	UserID     uuid.UUID `gorm:"primaryKey"`
	TenantID   uuid.UUID `gorm:"index"`
	ExternalID string
	Identified bool
	CreatedAt  time.Time
	LastSeen   time.Time
}

type MasterUser struct {
	AdminID             uuid.UUID        `gorm:"type:uuid;foreginKey"`
    UserID              uuid.UUID        `gorm:"type:uuid;primaryKey"`
    Email               string           `gorm:"type:text;uniqueIndex"`
    Phone               string           `gorm:"type:text;uniqueIndex"`
    Password            string           `gorm:"type:text"`
    FirstName           string           `gorm:"type:text"`
    LastName            string           `gorm:"type:text"`
    Age                 int              `gorm:"type:int"`
    GuardianEmail       string           `gorm:"type:text;index"`
    Location            string           `gorm:"type:text"`
    Tenants             []UserTenantLink `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
    CreatedAt           time.Time
    PasswordResetToken  string    `gorm:"type:text"`
    PasswordResetExpiry time.Time

    Role               string `gorm:"type:varchar(20);default:'viewer'"`
    CanManageConsent   bool   `gorm:"default:false"`
    CanManageGrievance bool   `gorm:"default:false"`
    CanManagePurposes  bool   `gorm:"default:false"`
    CanManageAuditLogs bool   `gorm:"default:false"`
}

type UserTenantLink struct {
	ID             uuid.UUID `gorm:"primaryKey"`
	UserID         uuid.UUID `gorm:"index"`
	TenantID       uuid.UUID `gorm:"index"`
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
	ID             uuid.UUID      `gorm:"primaryKey"`
	UserID         uuid.UUID      `gorm:"index"`
	Purposes       dto.ConsentPurposes `gorm:"type:jsonb" json:"purposes"`
	PolicySnapshot datatypes.JSON `gorm:"type:jsonb" json:"policy_snapshot"`
	Signature      string
	GeoRegion      string
	Jurisdiction   string
	TenantID       uuid.UUID `gorm:"index"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ConsentLink struct {
	ID              uuid.UUID `gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Link            string    `gorm:"type:text;not null;unique"`
	TenantID        uuid.UUID `gorm:"type:uuid;not null;index"`
	Name            string
	SubmissionCount int       `gorm:"default:0"`
	Metadata        []byte    `gorm:"type:jsonb;default:null"`
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
	VendorID            uuid.UUID        `gorm:"primaryKey" json:"id"`
	Company             string
	Email               string           `gorm:"type:text;uniqueIndex"`   
	Address             string
}