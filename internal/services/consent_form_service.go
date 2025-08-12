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
	form := &models.ConsentForm{
		ID:                      uuid.New(),
		TenantID:                tenantID,
		Name:                    req.Name,
		Title:                   req.Title,
		Description:             req.Description,
		DataCollectionAndUsage:  req.DataCollectionAndUsage,
		DataSharingAndTransfers: req.DataSharingAndTransfers,
		DataRetentionPeriod:     req.DataRetentionPeriod,
		UserRightsSummary:       req.UserRightsSummary,
		TermsAndConditions:      req.TermsAndConditions,
		PrivacyPolicy:           req.PrivacyPolicy,
	}
	return s.repo.CreateConsentForm(form)
}

func (s *ConsentFormService) UpdateConsentForm(formID uuid.UUID, req *dto.UpdateConsentFormRequest) (*models.ConsentForm, error) {
	form, err := s.repo.GetConsentFormByID(formID)
	if err != nil {
		return nil, err
	}

	if req.Name != "" {
		form.Name = req.Name
	}
	if req.Title != "" {
		form.Title = req.Title
	}
	if req.Description != "" {
		form.Description = req.Description
	}
	if req.DataCollectionAndUsage != "" {
		form.DataCollectionAndUsage = req.DataCollectionAndUsage
	}
	if req.DataSharingAndTransfers != "" {
		form.DataSharingAndTransfers = req.DataSharingAndTransfers
	}
	if req.DataRetentionPeriod != "" {
		form.DataRetentionPeriod = req.DataRetentionPeriod
	}
	if req.UserRightsSummary != "" {
		form.UserRightsSummary = req.UserRightsSummary
	}
	if req.TermsAndConditions != "" {
		form.TermsAndConditions = req.TermsAndConditions
	}
	if req.PrivacyPolicy != "" {
		form.PrivacyPolicy = req.PrivacyPolicy
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
