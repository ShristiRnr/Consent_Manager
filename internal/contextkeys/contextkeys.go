package contextkeys

// Context keys (use typed constants to avoid key collisions)
type contextKey string

const (
	FiduciaryClaimsKey contextKey = "fiduciaryClaims"
	UserClaimsKey      contextKey = "userClaims"
	APIKeyClaimsKey    contextKey = "apiKeyClaims"
	TenantIDKey        contextKey = "tenantID"
)