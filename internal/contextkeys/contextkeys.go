package contextkeys

// Context keys (use typed constants to avoid key collisions)
type contextKey string

const (
	AdminClaimsKey  contextKey = "adminClaims"
	UserClaimsKey   contextKey = "userClaims"
	APIKeyClaimsKey contextKey = "apiKeyClaims"
	TenantIDKey     contextKey = "tenantID"
)