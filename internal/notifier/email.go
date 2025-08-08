package notifier

import (
	"github.com/rs/zerolog/log"
)

func SendConsentConfirmationEmail(userEmail, purpose string, newStatus bool) {
	log.Info().
		Str("email", userEmail).
		Str("purpose", purpose).
		Bool("status", newStatus).
		Msg("Simulated email sent to user")
}

// func EnqueueWebhook(db *gorm.DB, tenantID uuid.UUID, event string, payload interface{}) error {
// 	data, _ := json.Marshal(payload)
// 	return db.Create(&models.WebhookQueue{
// 		ID:         uuid.New(),
// 		TenantID:   tenantID,
// 		Event:      event,
// 		Payload:    datatypes.JSON(data),
// 		Attempts:   0,
// 		MaxRetries: 5,
// 		NextTryAt:  time.Now(),
// 		CreatedAt:  time.Now(),
// 	}).Error
// }
