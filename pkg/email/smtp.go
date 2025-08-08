package email

import (
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

func AdminPasswordResetEmailSender(db *gorm.DB) func(to, token string) error {
	return func(to, token string) error {
		// Find admin by email
		var admin models.AdminUser
		if err := db.Where("email = ?", to).First(&admin).Error; err != nil {
			return fmt.Errorf("admin not found: %w", err)
		}
		// Find their tenant
		var tenant models.Tenant
		if err := db.Where("tenant_id = ?", admin.TenantID).First(&tenant).Error; err != nil {
			return fmt.Errorf("tenant not found: %w", err)
		}
		resetLink := fmt.Sprintf("https://your-app-domain.com/reset-password?token=%s", token)
		body := fmt.Sprintf(
			"You requested a password reset as an admin. Click below:\n\n%s\n\nIf you did not request this, please ignore this email.",
			resetLink,
		)
		return SendTenantEmail(tenant, to, "Password Reset", body)
	}
}

func UserPasswordResetEmailSender(masterTenant models.Tenant) func(to, token string) error {
	return func(to, token string) error {
		resetLink := fmt.Sprintf("https://your-app-domain.com/reset-password?token=%s", token)
		body := fmt.Sprintf(
			"You requested a password reset. Click below:\n\n%s\n\nIf you did not request this, please ignore this email.",
			resetLink,
		)
		return SendTenantEmail(masterTenant, to, "Password Reset", body)
	}
}
