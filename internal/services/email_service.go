package services

import (
	"gopkg.in/gomail.v2"
)

type EmailService struct {
	dialer *gomail.Dialer
}

func NewEmailService(host string, port int, username, password string) *EmailService {
	dialer := gomail.NewDialer(host, port, username, password)
	return &EmailService{dialer: dialer}
}

func (s *EmailService) Send(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.dialer.Username)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return s.dialer.DialAndSend(m)
}
