package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"consultrnr/consent-manager/internal/breach"
	"consultrnr/consent-manager/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BreachReportingService handles automated breach reporting to the Data Protection Board
type BreachReportingService struct {
	DB *gorm.DB
}

// NewBreachReportingService creates a new breach reporting service
func NewBreachReportingService(db *gorm.DB) *BreachReportingService {
	return &BreachReportingService{DB: db}
}

// CheckAndReportBreach checks if a breach needs to be reported to the DPB and reports it if necessary
func (s *BreachReportingService) CheckAndReportBreach(ctx context.Context, breachID uuid.UUID) error {
	var dbBreach models.BreachNotification
	if err := s.DB.Where("id = ?", breachID).First(&dbBreach).Error; err != nil {
		return fmt.Errorf("failed to retrieve breach: %w", err)
	}

	// Create breach notification entity for DPDP validation
	// Convert string values to breach package types
	breachType := breach.BreachType(dbBreach.BreachType)
	breachSeverity := breach.BreachSeverity(dbBreach.Severity)
	
	breachEntity := &breach.BreachNotification{
		ID:                   dbBreach.ID,
		TenantID:             dbBreach.TenantID,
		Description:          dbBreach.Description,
		BreachDate:           dbBreach.BreachDate,
		DetectionDate:        dbBreach.DetectionDate,
		NotificationDate:     dbBreach.NotificationDate,
		AffectedUsersCount:   dbBreach.AffectedUsersCount,
		NotifiedUsersCount:   dbBreach.NotifiedUsersCount,
		Severity:             breachSeverity,
		BreachType:           breachType,
		RequiresDPBReporting: dbBreach.RequiresDPBReporting,
		DPBReported:          dbBreach.DPBReported,
		DPBReportedDate:      dbBreach.DPBReportedDate,
		DPBReportReference:   dbBreach.DPBReportReference,
		RemedialActions:      []string{}, // Will be populated from JSON
		PreventiveMeasures:   []string{}, // Will be populated from JSON
		InvestigationSummary: dbBreach.InvestigationSummary,
		InvestigatedBy:       dbBreach.InvestigatedBy,
		InvestigationDate:    dbBreach.InvestigationDate,
		ComplianceStatus:     dbBreach.ComplianceStatus,
		ComplianceNotes:      dbBreach.ComplianceNotes,
		CreatedAt:            dbBreach.CreatedAt,
		UpdatedAt:            dbBreach.UpdatedAt,
	}

	// Check if the breach requires DPB reporting
	if breachEntity.IsDPBReportable() && !breachEntity.DPBReported {
		return s.ReportBreachToDPB(ctx, breachEntity)
	}

	return nil
}

// ReportBreachToDPB reports a breach to the Data Protection Board
func (s *BreachReportingService) ReportBreachToDPB(ctx context.Context, breach *breach.BreachNotification) error {
	// In a real implementation, this would make an API call to the DPB
	// For now, we'll simulate the reporting process
	
	log.Printf("Reporting breach %s to Data Protection Board", breach.ID.String())
	
	// Generate the report content
	reportContent := breach.GenerateDPBReport()
	
	// In a real implementation, we would send this to the DPB API
	// For simulation purposes, we'll just log it
	log.Printf("DPB Report Content: %+v", reportContent)
	
	// Generate a mock report reference
	reportReference := fmt.Sprintf("DPB-REPORT-%s-%d", breach.ID.String()[:8], time.Now().Unix())
	
	// Mark the breach as reported
	breach.MarkAsReportedToDPB(reportReference)
	
	// Update the database
	var dbBreach models.BreachNotification
	if err := s.DB.Where("id = ?", breach.ID).First(&dbBreach).Error; err != nil {
		return fmt.Errorf("failed to retrieve breach for update: %w", err)
	}
	
	dbBreach.DPBReported = true
	dbBreach.DPBReportedDate = breach.DPBReportedDate
	dbBreach.DPBReportReference = breach.DPBReportReference
	dbBreach.UpdatedAt = time.Now()
	
	if err := s.DB.Save(&dbBreach).Error; err != nil {
		return fmt.Errorf("failed to update breach: %w", err)
	}
	
	log.Printf("Successfully reported breach %s to Data Protection Board with reference %s", 
		breach.ID.String(), reportReference)
	
	return nil
}

// ProcessPendingBreachReports processes all pending breach reports that need to be sent to the DPB
func (s *BreachReportingService) ProcessPendingBreachReports(ctx context.Context) error {
	// Find all breaches that require DPB reporting but haven't been reported yet
	var breaches []models.BreachNotification
	if err := s.DB.Where("requires_dpb_reporting = ? AND dpb_reported = ?", true, false).Find(&breaches).Error; err != nil {
		return fmt.Errorf("failed to retrieve pending breach reports: %w", err)
	}
	
	log.Printf("Found %d breaches pending DPB reporting", len(breaches))
	
	for _, dbBreach := range breaches {
		// Check if the breach is reportable according to DPDP requirements
		breachEntity := &breach.BreachNotification{
			ID:                   dbBreach.ID,
			TenantID:             dbBreach.TenantID,
			Description:          dbBreach.Description,
			BreachDate:           dbBreach.BreachDate,
			DetectionDate:        dbBreach.DetectionDate,
			NotificationDate:     dbBreach.NotificationDate,
			AffectedUsersCount:   dbBreach.AffectedUsersCount,
			NotifiedUsersCount:   dbBreach.NotifiedUsersCount,
			Severity:             breach.BreachSeverity(dbBreach.Severity),
			BreachType:           breach.BreachType(dbBreach.BreachType),
			RequiresDPBReporting: dbBreach.RequiresDPBReporting,
			DPBReported:          dbBreach.DPBReported,
			DPBReportedDate:      dbBreach.DPBReportedDate,
			DPBReportReference:   dbBreach.DPBReportReference,
			RemedialActions:      []string{}, // Will be populated from JSON
			PreventiveMeasures:   []string{}, // Will be populated from JSON
			InvestigationSummary: dbBreach.InvestigationSummary,
			InvestigatedBy:       dbBreach.InvestigatedBy,
			InvestigationDate:    dbBreach.InvestigationDate,
			ComplianceStatus:     dbBreach.ComplianceStatus,
			ComplianceNotes:      dbBreach.ComplianceNotes,
			CreatedAt:            dbBreach.CreatedAt,
			UpdatedAt:            dbBreach.UpdatedAt,
		}
		
		if breachEntity.IsDPBReportable() {
			if err := s.ReportBreachToDPB(ctx, breachEntity); err != nil {
				log.Printf("Failed to report breach %s to DPB: %v", dbBreach.ID.String(), err)
				// Continue processing other breaches
				continue
			}
		}
	}
	
	return nil
}
