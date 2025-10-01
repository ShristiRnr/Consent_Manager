package services

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"
	"fmt"

	"github.com/google/uuid"
)

type ConsentFormService struct {
	repo *repository.ConsentFormRepository
}

func NewConsentFormService(repo *repository.ConsentFormRepository) *ConsentFormService {
	return &ConsentFormService{repo: repo}
}

func (s *ConsentFormService) CreateConsentForm(tenantID uuid.UUID, req *dto.CreateConsentFormRequest) (*models.ConsentForm, error) {
	var orgID uuid.UUID
	var err error
	if req.OrganizationEntityID != nil && *req.OrganizationEntityID != "" {
		orgID, err = uuid.Parse(*req.OrganizationEntityID)
		if err != nil {
			return nil, fmt.Errorf("invalid organizationEntityId: %w", err)
		}
	}

	form := &models.ConsentForm{
		ID:       uuid.New(),
		TenantID: tenantID,
		Name:     req.Name,
		Title:    req.Title,
	}

	if req.Description != nil {
		form.Description = *req.Description
	}
	if req.Department != nil {
		form.Department = *req.Department
	}
	if req.Project != nil {
		form.Project = *req.Project
	}
	form.OrganizationEntityID = orgID
	if req.DataRetentionPeriod != nil {
		form.DataRetentionPeriod = *req.DataRetentionPeriod
	}
	if req.UserRightsSummary != nil {
		form.UserRightsSummary = *req.UserRightsSummary
	}
	if req.TermsAndConditions != nil {
		form.TermsAndConditions = *req.TermsAndConditions
	}
	if req.PrivacyPolicy != nil {
		form.PrivacyPolicy = *req.PrivacyPolicy
	}
	return s.repo.CreateConsentForm(form)
}

func (s *ConsentFormService) UpdateConsentForm(formID uuid.UUID, req *dto.UpdateConsentFormRequest) (*models.ConsentForm, error) {
	form, err := s.repo.GetConsentFormByID(formID)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		form.Name = *req.Name
	}
	if req.Title != nil {
		form.Title = *req.Title
	}
	if req.Description != nil {
		form.Description = *req.Description
	}
	if req.Department != nil {
		form.Department = *req.Department
	}
	if req.Project != nil {
		form.Project = *req.Project
	}
	if req.OrganizationEntityID != nil {
		if *req.OrganizationEntityID == "" {
			form.OrganizationEntityID = uuid.Nil
		} else {
			orgID, err := uuid.Parse(*req.OrganizationEntityID)
			if err != nil {
				return nil, fmt.Errorf("invalid organizationEntityId: %w", err)
			}
			form.OrganizationEntityID = orgID
		}
	}
	if req.DataRetentionPeriod != nil {
		form.DataRetentionPeriod = *req.DataRetentionPeriod
	}
	if req.UserRightsSummary != nil {
		form.UserRightsSummary = *req.UserRightsSummary
	}
	if req.TermsAndConditions != nil {
		form.TermsAndConditions = *req.TermsAndConditions
	}
	if req.PrivacyPolicy != nil {
		form.PrivacyPolicy = *req.PrivacyPolicy
	}

	return s.repo.UpdateConsentForm(form)
}

func (s *ConsentFormService) DeleteConsentForm(formID uuid.UUID) error {
	return s.repo.DeleteConsentForm(formID)
}

func (s *ConsentFormService) GetConsentFormByID(formID uuid.UUID) (*models.ConsentForm, error) {
	return s.repo.GetConsentFormByID(formID)
}

func (s *ConsentFormService) ListConsentForms(tenantID uuid.UUID) ([]models.ConsentForm, error) {
	return s.repo.ListConsentForms(tenantID)
}

func (s *ConsentFormService) AddPurposeToConsentForm(formID uuid.UUID, req *dto.AddPurposeToConsentFormRequest) (*models.ConsentFormPurpose, error) {
	purposeID, err := uuid.Parse(req.PurposeID)
	if err != nil {
		return nil, err
	}
	return s.repo.AddPurposeToConsentForm(formID, purposeID, req.DataObjects, req.VendorIDs, req.ExpiryInDays)
}

func (s *ConsentFormService) UpdatePurposeInConsentForm(formID uuid.UUID, purposeID uuid.UUID, req *dto.UpdatePurposeInConsentFormRequest) (*models.ConsentFormPurpose, error) {
	return s.repo.UpdatePurposeInConsentForm(formID, purposeID, req.DataObjects, req.VendorIDs, req.ExpiryInDays)
}

func (s *ConsentFormService) RemovePurposeFromConsentForm(formID, purposeID uuid.UUID) error {
	return s.repo.RemovePurposeFromConsentForm(formID, purposeID)
}

func (s *ConsentFormService) GetIntegrationScript(formID uuid.UUID) *dto.IntegrationScriptResponse {
	cfg := config.LoadConfig()
	script := fmt.Sprintf(`<script>\n\tfunction openConsentForm() {\n\t\twindow.open('%s/#/consent/%s', 'ConsentForm', 'width=600,height=400');\n\t}\n</script>`, cfg.FrontendBaseURL, formID.String())

	return &dto.IntegrationScriptResponse{Script: script}
}

func (s *ConsentFormService) PublishConsentForm(formID uuid.UUID) error {
	return s.repo.PublishConsentForm(formID)
}
