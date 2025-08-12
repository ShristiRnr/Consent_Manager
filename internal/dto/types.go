package dto

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Purpose struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Consented bool      `json:"consented"`
	Version   string    `json:"version,omitempty"`
	Language  string    `json:"language,omitempty"`
}

type ConsentPurpose struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Status      bool       `json:"status"` // e.g., "active", "withdrawn"
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}

type ConsentPurposes struct {
	Purposes []ConsentPurpose `json:"purposes"`
}

type CreateConsentRequest struct {
	Input    string    `json:"input"` // email or phone
	Purposes []Purpose `json:"purposes"`
	TenantID string    `json:"tenantId"`
}

// Implement the driver.Valuer interface
func (c ConsentPurposes) Value() (driver.Value, error) {
	return json.Marshal(c.Purposes)
}

// Implement the sql.Scanner interface
func (c *ConsentPurposes) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte for ConsentPurposes, got %T", value)
	}
	return json.Unmarshal(bytes, &c.Purposes)
}

type VendorConsentRequest struct {
	Input    string    `json:"input"`    // email/phone
	TenantID string    `json:"tenantId"` // tenant context
	Purposes []Purpose `json:"purposes"` // list of purpose names and statuses
}

type AdminConsentOverrideRequest struct {
	UID      string    `json:"uid"`
	TenantID string    `json:"tenantId"`
	Purposes []Purpose `json:"purposes"`
}

type CreateGrievanceRequest struct {
	UserID               string `json:"userId"`
	TenantID             string `json:"tenantId,omitempty"` // filled by server, not client
	GrievanceType        string `json:"grievanceType"`
	GrievanceSubject     string `json:"grievanceSubject"`
	GrievanceDescription string `json:"grievanceDescription"`
	Category             string `json:"category,omitempty"`
	Priority             string `json:"priority,omitempty"`
}

type UpdateGrievanceRequest struct {
	Status     string `json:"status" binding:"required,oneof=open in_progress escalated closed"`
	AssignedTo string `json:"assignedTo,omitempty" binding:"omitempty,uuid"`
}

type UpdateGrievanceDetailsRequest struct {
	GrievanceType        string `json:"grievanceType,omitempty"`
	GrievanceSubject     string `json:"grievanceSubject,omitempty"`
	GrievanceDescription string `json:"grievanceDescription,omitempty"`
	Category             string `json:"category,omitempty"`
	Priority             string `json:"priority,omitempty"`
}

type ListGrievanceRequest struct {
	UserID   string `json:"userId,omitempty" binding:"omitempty,uuid"`
	TenantID string `json:"tenantId" binding:"required,uuid"`
	Status   string `json:"status,omitempty" binding:"omitempty,oneof=open in_progress escalated closed"`
	Page     int    `json:"page" binding:"required,gte=1"`
	Limit    int    `json:"limit" binding:"required,gte=1,lte=100"`
}

type CreateGrievanceCommentRequest struct {
	GrievanceID string `json:"grievanceId" binding:"required,uuid"`
	UserID      string `json:"userId" binding:"required,uuid"`
	AdminID     string `json:"adminId,omitempty" binding:"omitempty,uuid"`
	Comment     string `json:"comment" binding:"required"`
}

type ReviewPageData struct {
	UID      string           `json:"uid"`
	TenantID uuid.UUID        `json:"tenantId"`
	Purposes []ConsentPurpose `json:"purposes"`
}

type ConsentHistoryEntry struct {
	Action       string    `json:"action"`
	Purposes     []Purpose `json:"purposes"`
	Timestamp    time.Time `json:"timestamp"`
	ChangedBy    string    `json:"changedBy"`
	GeoRegion    string    `json:"geoRegion,omitempty"`
	Jurisdiction string    `json:"jurisdiction,omitempty"`
}

type NotificationResponse struct {
	ID      uuid.UUID `json:"id"`
	Title   string    `json:"title"`
	Body    string    `json:"body"`
	Unread  bool      `json:"unread"`
	Created time.Time `json:"createdAt"`
}

type CreateDSRRequest struct {
	UserID   string `json:"userId" binding:"required,uuid"`
	TenantID string `json:"tenantId" binding:"required,uuid"`
	Type     string `json:"type" binding:"required,oneof=access delete rectify port restrict object"`
}

// Consent Form DTOs
type CreateConsentFormRequest struct {
	Name                    string `json:"name" binding:"required"`
	Title                   string `json:"title" binding:"required"`
	Description             string `json:"description"`
	DataCollectionAndUsage  string `json:"dataCollectionAndUsage"`
	DataSharingAndTransfers string `json:"dataSharingAndTransfers"`
	DataRetentionPeriod     string `json:"dataRetentionPeriod"`
	UserRightsSummary       string `json:"userRightsSummary"`
	TermsAndConditions      string `json:"termsAndConditions"`
	PrivacyPolicy           string `json:"privacyPolicy"`
}

type UpdateConsentFormRequest struct {
	Name                    string `json:"name"`
	Title                   string `json:"title"`
	Description             string `json:"description"`
	DataCollectionAndUsage  string `json:"dataCollectionAndUsage"`
	DataSharingAndTransfers string `json:"dataSharingAndTransfers"`
	DataRetentionPeriod     string `json:"dataRetentionPeriod"`
	UserRightsSummary       string `json:"userRightsSummary"`
	TermsAndConditions      string `json:"termsAndConditions"`
	PrivacyPolicy           string `json:"privacyPolicy"`
}

type AddPurposeToConsentFormRequest struct {
	PurposeID    string   `json:"purposeId" binding:"required,uuid"`
	DataObjects  []string `json:"dataObjects"`
	VendorIDs    []string `json:"vendorIds"`
	ExpiryInDays int      `json:"expiryInDays"`
}

type UpdatePurposeInConsentFormRequest struct {
	DataObjects  []string `json:"dataObjects"`
	VendorIDs    []string `json:"vendorIds"`
	ExpiryInDays int      `json:"expiryInDays"`
}

type ConsentFormPurposeResponse struct {
	PurposeID    string   `json:"purposeId"`
	PurposeName  string   `json:"purposeName"`
	DataObjects  []string `json:"dataObjects"`
	VendorIDs    []string `json:"vendorIds"`
	ExpiryInDays int      `json:"expiryInDays"`
}

type ConsentFormResponse struct {
	ID                      string                       `json:"id"`
	Name                    string                       `json:"name"`
	Title                   string                       `json:"title"`
	Description             string                       `json:"description"`
	DataCollectionAndUsage  string                       `json:"dataCollectionAndUsage"`
	DataSharingAndTransfers string                       `json:"dataSharingAndTransfers"`
	DataRetentionPeriod     string                       `json:"dataRetentionPeriod"`
	UserRightsSummary       string                       `json:"userRightsSummary"`
	TermsAndConditions      string                       `json:"termsAndConditions"`
	PrivacyPolicy           string                       `json:"privacyPolicy"`
	Purposes                []ConsentFormPurposeResponse `json:"purposes"`
	CreatedAt               time.Time                    `json:"createdAt"`
	UpdatedAt               time.Time                    `json:"updatedAt"`
}

type SubmitConsentRequest struct {
	Purposes []PurposeConsent `json:"purposes"`
}

type PurposeConsent struct {
	PurposeID string `json:"purposeId"`
	Consented bool   `json:"consented"`
}

type IntegrationScriptResponse struct {
	Script string `json:"script"`
}

// Breach Notification DTOs
type CreateBreachNotificationRequest struct {
	Description        string    `json:"description" binding:"required"`
	BreachDate         time.Time `json:"breachDate" binding:"required"`
	DetectionDate      time.Time `json:"detectionDate" binding:"required"`
	AffectedUsersCount int       `json:"affectedUsersCount" binding:"required"`
	Status             string    `json:"status" binding:"required"`
}

type BreachNotificationResponse struct {
	ID                 uuid.UUID  `json:"id"`
	TenantID           uuid.UUID  `json:"tenantId"`
	Description        string     `json:"description"`
	BreachDate         time.Time  `json:"breachDate"`
	DetectionDate      time.Time  `json:"detectionDate"`
	AffectedUsersCount int        `json:"affectedUsersCount"`
	NotifiedUsersCount int        `json:"notifiedUsersCount"`
	Status             string     `json:"status"`
	ReportedToDPB      bool       `json:"reportedToDpb"`
	ReportedToDPBDate  *time.Time `json:"reportedToDpbDate,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
}
