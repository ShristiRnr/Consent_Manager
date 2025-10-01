package compliance

import (
	"fmt"
	"time"

	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
)

// DPDPComplianceValidator provides validation functions for DPDP compliance
type DPDPComplianceValidator struct{}

// NewDPDPComplianceValidator creates a new DPDP compliance validator
func NewDPDPComplianceValidator() *DPDPComplianceValidator {
	return &DPDPComplianceValidator{}
}

// ValidateConsentForm checks if a consent form meets DPDP requirements
func (v *DPDPComplianceValidator) ValidateConsentForm(form *models.ConsentForm) []string {
	var violations []string

	// Check if form has required fields per DPDP
	if form.Title == "" {
		violations = append(violations, "Consent form must have a title")
	}

	if form.Description == "" {
		violations = append(violations, "Consent form must have a description")
	}

	if form.DataRetentionPeriod == "" {
		violations = append(violations, "Consent form must specify data retention period")
	}

	if form.UserRightsSummary == "" {
		violations = append(violations, "Consent form must specify user rights summary")
	}

	if form.TermsAndConditions == "" {
		violations = append(violations, "Consent form must have terms and conditions")
	}

	if form.PrivacyPolicy == "" {
		violations = append(violations, "Consent form must have a privacy policy")
	}

	// Check if form has purposes
	if len(form.Purposes) == 0 {
		violations = append(violations, "Consent form must have at least one purpose")
	}

	return violations
}

// ValidatePurpose checks if a purpose meets DPDP requirements
func (v *DPDPComplianceValidator) ValidatePurpose(purpose *models.Purpose) []string {
	var violations []string

	if purpose.Name == "" {
		violations = append(violations, "Purpose must have a name")
	}

	if purpose.Description == "" {
		violations = append(violations, "Purpose must have a description")
	}

	if purpose.LegalBasis == "" {
		violations = append(violations, "Purpose must specify legal basis")
	}

	if purpose.Version == "" {
		violations = append(violations, "Purpose must have a version")
	}

	if purpose.Language == "" {
		violations = append(violations, "Purpose must specify language")
	}

	return violations
}

// ValidateDataPrincipal checks if a data principal record meets DPDP requirements
func (v *DPDPComplianceValidator) ValidateDataPrincipal(dp *models.DataPrincipal) []string {
	var violations []string

	if dp.FirstName == "" {
		violations = append(violations, "Data principal must have a first name")
	}

	if dp.LastName == "" {
		violations = append(violations, "Data principal must have a last name")
	}

	// For minors, guardian information is required
	if dp.Age < 18 && dp.GuardianEmail == "" {
		violations = append(violations, "Guardian email is required for minors")
	}

	return violations
}

// ValidateConsent checks if a consent record meets DPDP requirements
func (v *DPDPComplianceValidator) ValidateConsent(consent *models.Consent) []string {
	var violations []string

	if consent.UserID == uuid.Nil {
		violations = append(violations, "Consent must be associated with a user")
	}

	if consent.TenantID == uuid.Nil {
		violations = append(violations, "Consent must be associated with a tenant")
	}

	if len(consent.Purposes.Purposes) == 0 {
		violations = append(violations, "Consent must specify at least one purpose")
	}

	if consent.Signature == "" {
		violations = append(violations, "Consent must have a signature")
	}

	if consent.GeoRegion == "" {
		violations = append(violations, "Consent must specify geographic region")
	}

	if consent.Jurisdiction == "" {
		violations = append(violations, "Consent must specify jurisdiction")
	}

	return violations
}

// ValidateDataProcessingAgreement checks if a DPA meets DPDP requirements
func (v *DPDPComplianceValidator) ValidateDataProcessingAgreement(dpa *models.Vendor) []string {
	var violations []string

	if dpa.Company == "" {
		violations = append(violations, "DPA must specify the company name")
	}

	if dpa.Email == "" {
		violations = append(violations, "DPA must specify the company email")
	}

	if dpa.Address == "" {
		violations = append(violations, "DPA must specify the company address")
	}

	return violations
}

// ValidateBreachNotification checks if a breach notification meets DPDP requirements
func (v *DPDPComplianceValidator) ValidateBreachNotification(bn *models.BreachNotification) []string {
	var violations []string

	if bn.Description == "" {
		violations = append(violations, "Breach notification must have a description")
	}

	if bn.BreachDate.IsZero() {
		violations = append(violations, "Breach notification must specify breach date")
	}

	if bn.DetectionDate.IsZero() {
		violations = append(violations, "Breach notification must specify detection date")
	}

	if bn.Status == "" {
		violations = append(violations, "Breach notification must specify status")
	}

	// DPDP requires reporting to DPB within a specific timeframe
	if time.Since(bn.DetectionDate) > 7*24*time.Hour && !bn.DPBReported {
		violations = append(violations, fmt.Sprintf("Breach must be reported to DPB within 7 days of detection (detected %v ago)", time.Since(bn.DetectionDate)))
	}

	return violations
}
