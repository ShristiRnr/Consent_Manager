package consent

import (
	"time"

	"github.com/google/uuid"
)

// DPDPConsentType represents the specific types of consent required under DPDP
type DPDPConsentType string

const (
	// ExplicitConsent is for clear, affirmative consent for specific purposes
	ExplicitConsent DPDPConsentType = "explicit"
	
	// ImpliedConsent is for consent that can be reasonably inferred from actions
	ImpliedConsent DPDPConsentType = "implied"
	
	// DeemedConsent is for consent that is deemed given under specific circumstances
	DeemedConsent DPDPConsentType = "deemed"
	
	// WithdrawnConsent indicates consent has been explicitly withdrawn
	WithdrawnConsent DPDPConsentType = "withdrawn"
)

// ConsentGranularity represents the level of detail in consent
type ConsentGranularity string

const (
	// PurposeLevelGranularity means consent is given for entire purposes
	PurposeLevelGranularity ConsentGranularity = "purpose"
	
	// DataObjectLevelGranularity means consent is given for specific data objects
	DataObjectLevelGranularity ConsentGranularity = "data_object"
	
	// ProcessingActivityLevelGranularity means consent is given for specific processing activities
	ProcessingActivityLevelGranularity ConsentGranularity = "processing_activity"
)

// DPDPConsent represents a consent record with DPDP-specific attributes
type DPDPConsent struct {
	ID                   uuid.UUID         `json:"id"`
	DataPrincipalID      uuid.UUID         `json:"dataPrincipalId"`
	TenantID             uuid.UUID         `json:"tenantId"`
	ConsentType          DPDPConsentType   `json:"consentType"`
	Granularity          ConsentGranularity `json:"granularity"`
	PurposeID            *uuid.UUID        `json:"purposeId,omitempty"`
	DataObject           *string           `json:"dataObject,omitempty"`
	ProcessingActivity   *string           `json:"processingActivity,omitempty"`
	IsSpecific           bool              `json:"isSpecific"`
	IsInformed           bool              `json:"isInformed"`
	IsFreelyGiven        bool              `json:"isFreelyGiven"`
	IsUnambiguous        bool              `json:"isUnambiguous"`
	Status               string            `json:"status"` // granted, withdrawn, expired
	ExpiryDate           *time.Time        `json:"expiryDate,omitempty"`
	WithdrawalDate       *time.Time        `json:"withdrawalDate,omitempty"`
	ConsentGivenDate     time.Time         `json:"consentGivenDate"`
	LastUpdatedDate      time.Time         `json:"lastUpdatedDate"`
	ConsentMechanism     string            `json:"consentMechanism"` // web_form, api, physical, verbal
	ConsentLanguage      string            `json:"consentLanguage"`  // ISO language code
	ConsentVersion       string            `json:"consentVersion"`
	PolicySnapshot       string            `json:"policySnapshot"`
	Signature            *string           `json:"signature,omitempty"`
	Metadata             map[string]string `json:"metadata,omitempty"`
}

// ConsentAudit represents an audit record for consent operations
type ConsentAudit struct {
	ID              uuid.UUID   `json:"id"`
	ConsentID       uuid.UUID   `json:"consentId"`
	Action          string      `json:"action"` // granted, withdrawn, updated, accessed
	ActionPerformedBy string    `json:"actionPerformedBy"`
	ActionPerformedAt time.Time `json:"actionPerformedAt"`
	Details         string      `json:"details,omitempty"`
	IPAddress       string      `json:"ipAddress,omitempty"`
	UserAgent       string      `json:"userAgent,omitempty"`
}

// Validate checks if the DPDP consent record meets DPDP requirements
func (c *DPDPConsent) Validate() []string {
	var violations []string
	
	// Check if consent is specific
	if !c.IsSpecific {
		violations = append(violations, "Consent must be specific")
	}
	
	// Check if consent is informed
	if !c.IsInformed {
		violations = append(violations, "Consent must be informed")
	}
	
	// Check if consent is freely given
	if !c.IsFreelyGiven {
		violations = append(violations, "Consent must be freely given")
	}
	
	// Check if consent is unambiguous
	if !c.IsUnambiguous {
		violations = append(violations, "Consent must be unambiguous")
	}
	
	// For explicit consent, additional checks
	if c.ConsentType == ExplicitConsent {
		// Explicit consent must have a purpose
		if c.PurposeID == nil {
			violations = append(violations, "Explicit consent must specify a purpose")
		}
		
		// Explicit consent must have a mechanism recorded
		if c.ConsentMechanism == "" {
			violations = append(violations, "Explicit consent must record the mechanism used")
		}
	}
	
	// Check granularity requirements
	switch c.Granularity {
	case DataObjectLevelGranularity:
		if c.DataObject == nil || *c.DataObject == "" {
			violations = append(violations, "Data object level granularity requires specifying the data object")
		}
	case ProcessingActivityLevelGranularity:
		if c.ProcessingActivity == nil || *c.ProcessingActivity == "" {
			violations = append(violations, "Processing activity level granularity requires specifying the processing activity")
		}
	}
	
	return violations
}

// IsExpired checks if the consent has expired
func (c *DPDPConsent) IsExpired() bool {
	if c.ExpiryDate == nil {
		return false
	}
	return time.Now().After(*c.ExpiryDate)
}

// CanWithdraw checks if the consent can be withdrawn
func (c *DPDPConsent) CanWithdraw() bool {
	// Consent can be withdrawn if it's not already withdrawn and not expired
	return c.Status != "withdrawn" && !c.IsExpired()
}

// Withdraw marks the consent as withdrawn
func (c *DPDPConsent) Withdraw() {
	c.Status = "withdrawn"
	withdrawalDate := time.Now()
	c.WithdrawalDate = &withdrawalDate
	c.LastUpdatedDate = withdrawalDate
}
