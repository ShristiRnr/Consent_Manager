package services

import (
	"consultrnr/consent-manager/internal/dto"
	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/repository"
	"time"

	"github.com/google/uuid"
)

type UserConsentService struct {
	repo            *repository.UserConsentRepository
	consentFormRepo *repository.ConsentFormRepository
}

func NewUserConsentService(repo *repository.UserConsentRepository, consentFormRepo *repository.ConsentFormRepository) *UserConsentService {
	return &UserConsentService{repo: repo, consentFormRepo: consentFormRepo}
}

func (s *UserConsentService) SubmitConsent(userID, tenantID, formID uuid.UUID, req *dto.SubmitConsentRequest) error {
	form, err := s.consentFormRepo.GetConsentFormByID(formID)
	if err != nil {
		return err
	}

	for _, purposeConsent := range req.Purposes {
		purposeID, err := uuid.Parse(purposeConsent.PurposeID)
		if err != nil {
			continue // or handle error
		}

		var expiry *time.Time
		for _, formPurpose := range form.Purposes {
			if formPurpose.PurposeID == purposeID {
				if formPurpose.ExpiryInDays > 0 {
					now := time.Now()
					expiryDate := now.AddDate(0, 0, formPurpose.ExpiryInDays)
					expiry = &expiryDate
				}
				break
			}
		}

		userConsent := &models.UserConsent{
			ID:            uuid.New(),
			UserID:        userID,
			PurposeID:     purposeID,
			TenantID:      tenantID,
			ConsentFormID: formID,
			Status:        purposeConsent.Consented,
			ExpiresAt:     expiry,
		}

		_, err = s.repo.CreateUserConsent(userConsent)
		if err != nil {
			// Handle error, maybe rollback transaction
		}
	}

	return nil
}

func (s *UserConsentService) WithdrawConsent(userID, purposeID, tenantID uuid.UUID) error {
	userConsent, err := s.repo.GetUserConsent(userID, purposeID, tenantID)
	if err != nil {
		return err
	}

	userConsent.Status = false
	_, err = s.repo.UpdateUserConsent(userConsent)
	return err
}

func (s *UserConsentService) GetUserConsents(userID, tenantID uuid.UUID) ([]models.UserConsent, error) {
	return s.repo.ListUserConsents(userID, tenantID)
}

func (s *UserConsentService) GetUserConsentForPurpose(userID, purposeID, tenantID uuid.UUID) (*models.UserConsent, error) {
	return s.repo.GetUserConsent(userID, purposeID, tenantID)
}
