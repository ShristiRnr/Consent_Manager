package email

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/models"
	"encoding/json"
	"fmt"
	"net/smtp"

	"gorm.io/gorm"
)

type SMTPConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
	From string `json:"from"`
}

func SendTenantEmail(tenant models.Tenant, to, subject, body string) error {
	var cfg SMTPConfig
	if err := json.Unmarshal(tenant.Config, &cfg); err != nil {
		return fmt.Errorf("invalid SMTP config: %w", err)
	}
	auth := smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", cfg.From, to, subject, body)
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	return smtp.SendMail(addr, auth, cfg.From, []string{to}, []byte(msg))
}

func FiduciaryPasswordResetEmailSender(db *gorm.DB) func(to, token string) error {
	return func(to, token string) error {
		// Find fiduciary by email
		var fiduciary models.FiduciaryUser
		if err := db.Where("email = ?", to).First(&fiduciary).Error; err != nil {
			return fmt.Errorf("fiduciary not found: %w", err)
		}
		// Find their tenant
		var tenant models.Tenant
		if err := db.Where("tenant_id = ?", fiduciary.TenantID).First(&tenant).Error; err != nil {
			return fmt.Errorf("tenant not found: %w", err)
		}
		cfg := config.LoadConfig()
		resetLink := fmt.Sprintf("%s/reset-password?token=%s", cfg.BaseURL, token)
		body := fmt.Sprintf(
			"You requested a password reset as a fiduciary. Click below:\n\n%s\n\nIf you did not request this, please ignore this email.",
			resetLink,
		)
		return SendTenantEmail(tenant, to, "Password Reset", body)
	}
}

func UserPasswordResetEmailSender(masterTenant models.Tenant) func(to, token string) error {
	return func(to, token string) error {
		cfg := config.LoadConfig()
		resetLink := fmt.Sprintf("%s/reset-password?token=%s", cfg.BaseURL, token)
		body := fmt.Sprintf(
			"You requested a password reset. Click below:\n\n%s\n\nIf you did not request this, please ignore this email.",
			resetLink,
		)
		return SendTenantEmail(masterTenant, to, "Password Reset", body)
	}
}
