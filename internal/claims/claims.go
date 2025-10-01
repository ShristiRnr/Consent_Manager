package claims

import (
	"github.com/golang-jwt/jwt/v4"
)

type DataPrincipalClaims struct {
	PrincipalID string `json:"principalId"`
	TenantID    string `json:"tenantId"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	TokenType   string `json:"typ"`
	jwt.RegisteredClaims
}

type FiduciaryClaims struct {
	FiduciaryID    string          `json:"fiduciaryId"`
	TenantID       string          `json:"tenantId"`
	Roles          []string        `json:"roles"`
	Permissions    map[string]bool `json:"permissions"`
	ImpersonatorID string          `json:"impersonatorId,omitempty"` // ID of the admin impersonating this user
	Role           string          `json:"role"`                     // Deprecated
	Type           string          `json:"typ"`
	jwt.RegisteredClaims
}
