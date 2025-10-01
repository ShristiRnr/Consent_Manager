package services

import (
	"bytes"
	"consultrnr/consent-manager/internal/models"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"consultrnr/consent-manager/pkg/log"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type WebhookService struct {
	DB *gorm.DB
}

func NewWebhookService(db *gorm.DB) *WebhookService {
	return &WebhookService{DB: db}
}

// Event represents a webhook event payload.
type Event struct {
	ID        string      `json:"id"`
	EventType string      `json:"eventType"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Dispatch sends an event to all registered and active webhooks for a given tenant and event type.
func (s *WebhookService) Dispatch(tenantID uuid.UUID, eventType string, data interface{}) {
	var webhooks []models.Webhook
	// Find webhooks that are active and subscribed to the event type
	s.DB.Where("tenant_id = ? AND is_active = true AND ? = ANY(event_types)", tenantID, eventType).Find(&webhooks)

	if len(webhooks) == 0 {
		return
	}

	eventPayload := Event{
		ID:        "evt_" + uuid.New().String(),
		EventType: eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	payloadBytes, err := json.Marshal(eventPayload)
	if err != nil {
		log.Logger.Error().Err(err).Msg("Failed to marshal webhook payload")
		return
	}

	for _, webhook := range webhooks {
		go s.send(webhook, payloadBytes)
	}
}

// send performs the HTTP POST request for a single webhook.
func (s *WebhookService) send(webhook models.Webhook, payload []byte) {
	// Sign the payload
	mac := hmac.New(sha256.New, []byte(webhook.Secret))
	mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest("POST", webhook.URL, bytes.NewBuffer(payload))
	if err != nil {
		log.Logger.Error().Err(err).Str("webhookId", webhook.ID.String()).Msg("Failed to create webhook request")
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Consent-Manager-Signature", signature)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)

	// Log the event attempt
	eventLog := models.WebhookEvent{
		ID:          uuid.New(),
		WebhookID:   webhook.ID,
		EventType:   "unknown", // This could be improved by passing eventType to send()
		Payload:     payload,
		AttemptedAt: time.Now(),
	}

	if err != nil || resp.StatusCode >= 300 {
		eventLog.Success = false
		eventLog.Response = "Failed to send"
		if err != nil {
			eventLog.Response = err.Error()
		} else {
			eventLog.Response = resp.Status
		}
	} else {
		eventLog.Success = true
		eventLog.Response = resp.Status
	}

	s.DB.Create(&eventLog)
}
