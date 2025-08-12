package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// DataProcessingAgreement represents a Data Processing Agreement between a tenant and a vendor
// This model implements DPDP requirements for DPA management
type DataProcessingAgreement struct {
	ID                   uuid.UUID `gorm:"type:uuid;primaryKey"`
	TenantID             uuid.UUID `gorm:"type:uuid;index"`
	VendorID             uuid.UUID `gorm:"type:uuid;index"`
	AgreementTitle       string    `gorm:"type:varchar(255)"`
	AgreementNumber      string    `gorm:"type:varchar(100);uniqueIndex"`
	Status               string    `gorm:"type:varchar(50)"` // pending, active, expired, terminated, revoked
	EffectiveDate        time.Time
	ExpiryDate           *time.Time
	ProcessingPurposes   datatypes.JSON `gorm:"type:jsonb"` // Array of processing purposes
	DataCategories       datatypes.JSON `gorm:"type:jsonb"` // Array of data categories
	ProcessingLocation   string         `gorm:"type:varchar(100)"` // Where data will be processed
	SubProcessingAllowed bool           `gorm:"default:false"`
	SecurityMeasures     datatypes.JSON `gorm:"type:jsonb"` // Array of security measures
	DataRetentionPeriod  string         `gorm:"type:varchar(100)"`
	DataSubjectRights    datatypes.JSON `gorm:"type:jsonb"` // Array of data subject rights
	BreachNotification   bool           `gorm:"default:false"`
	AuditRights          bool           `gorm:"default:false"`
	LiabilityCap         string         `gorm:"type:varchar(100)"`
	InsuranceCoverage    string         `gorm:"type:varchar(255)"`
	GoverningLaw         string         `gorm:"type:varchar(100)"`
	SignatoryName        string         `gorm:"type:varchar(255)"`
	SignatoryTitle       string         `gorm:"type:varchar(255)"`
	Signature            *string        `gorm:"type:text"`
	SignedDate           *time.Time
	TerminationDate      *time.Time
	CreatedAt            time.Time      `gorm:"autoCreateTime"`
	UpdatedAt            time.Time      `gorm:"autoUpdateTime"`
	Version              string         `gorm:"type:varchar(50)"`
	PreviousVersionID    *uuid.UUID     `gorm:"type:uuid"`
}

// EncryptedDataProcessingAgreement represents a DataProcessingAgreement with encrypted sensitive fields
type EncryptedDataProcessingAgreement struct {
	ID                   uuid.UUID `gorm:"type:uuid;primaryKey"`
	TenantID             uuid.UUID `gorm:"type:uuid;index"`
	VendorID             uuid.UUID `gorm:"type:uuid;index"`
	AgreementTitle       string    `gorm:"type:varchar(255)"`
	AgreementNumber      string    `gorm:"type:varchar(100);uniqueIndex"`
	Status               string    `gorm:"type:varchar(50)"` // pending, active, expired, terminated, revoked
	EffectiveDate        time.Time
	ExpiryDate           *time.Time
	ProcessingPurposes   datatypes.JSON `gorm:"type:jsonb"` // Array of processing purposes
	DataCategories       datatypes.JSON `gorm:"type:jsonb"` // Array of data categories
	ProcessingLocation   string         `gorm:"type:varchar(100)"` // Where data will be processed
	SubProcessingAllowed bool           `gorm:"default:false"`
	SecurityMeasures     datatypes.JSON `gorm:"type:jsonb"` // Array of security measures
	DataRetentionPeriod  string         `gorm:"type:varchar(100)"`
	DataSubjectRights    datatypes.JSON `gorm:"type:jsonb"` // Array of data subject rights
	BreachNotification   bool           `gorm:"default:false"`
	AuditRights          bool           `gorm:"default:false"`
	LiabilityCap         string         `gorm:"type:varchar(100)"`
	InsuranceCoverage    string         `gorm:"type:varchar(255)"`
	GoverningLaw         string         `gorm:"type:varchar(100)"`
	SignatoryName        string         `gorm:"type:varchar(255)"`
	SignatoryTitle       string         `gorm:"type:varchar(255)"`
	Signature            *string        `gorm:"type:text"`
	SignedDate           *time.Time
	TerminationDate      *time.Time
	CreatedAt            time.Time      `gorm:"autoCreateTime"`
	UpdatedAt            time.Time      `gorm:"autoUpdateTime"`
	Version              string         `gorm:"type:varchar(50)"`
	PreviousVersionID    *uuid.UUID     `gorm:"type:uuid"`
}

// BeforeCreate hook to set default values
func (dpa *DataProcessingAgreement) BeforeCreate(tx *gorm.DB) error {
	// Set default status if not provided
	if dpa.Status == "" {
		dpa.Status = "pending"
	}
	return nil
}

// DPAComplianceCheck represents a compliance check for a DPA
// This model tracks compliance verification activities as required by DPDP
type DPAComplianceCheck struct {
	ID              uuid.UUID `gorm:"type:uuid;primaryKey"`
	DPAID           uuid.UUID `gorm:"type:uuid;index"`
	CheckDate       time.Time
	CheckedBy       string    `gorm:"type:varchar(255)"`
	Compliant       bool      `gorm:"default:false"`
	Findings        datatypes.JSON `gorm:"type:jsonb"` // Array of findings
	RemedialActions datatypes.JSON `gorm:"type:jsonb"` // Array of remedial actions
	NextCheckDate   *time.Time
	CreatedAt       time.Time `gorm:"autoCreateTime"`
}
