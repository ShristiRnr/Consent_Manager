package dto

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Purpose struct {
	Name      string `json:"name"`
	Consented bool   `json:"consented"`
	Version   string `json:"version,omitempty"`
	Language  string `json:"language,omitempty"`
}

type ConsentPurpose struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Status      bool      `json:"status"` // e.g., "active", "withdrawn"
	Description string    `json:"description"`
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
