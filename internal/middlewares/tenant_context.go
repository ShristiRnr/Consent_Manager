package middlewares

import (
	"consultrnr/consent-manager/config"
	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/repository"
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/jwtlink"
	"context"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)


func TenantContextMiddleware(cfg config.Config, auditService *services.AuditService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
				token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
					return []byte(cfg.JWTSecret), nil
				})
				if err != nil || !token.Valid {
					return echo.NewHTTPError(401, "unauthorized")
				}
				claims, ok := token.Claims.(jwt.MapClaims)
				if !ok || claims["tenantId"] == nil {
					return echo.NewHTTPError(401, "invalid token claims")
				}
				c.Set("tenant_id", claims["tenantId"].(string))
				return next(c)
			}

			if tenantID := c.Request().Header.Get("X-Tenant-ID"); tenantID != "" {
				c.Set("tenant_id", tenantID)
				return next(c)
			}
			return echo.NewHTTPError(401, "unauthorized")
		}
	}
}

func TenantInjector(
	cfg config.Config,
	auditService *services.AuditService,
	requireUser bool,
	fn func(svc *services.ConsentService) echo.HandlerFunc,
) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			return echo.NewHTTPError(401, "Missing or invalid Authorization header")
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := jwtlink.ParseReviewToken(token)
		if err != nil {
			return echo.NewHTTPError(401, "invalid or expired token")
		}
		tenantID := claims.TenantID
		if tenantID == "" {
			return echo.NewHTTPError(400, "Missing tenant context")
		}
		if requireUser && c.Request().Header.Get("X-User-ID") == "" {
			return echo.NewHTTPError(400, "Missing X-User-ID header")
		}

		schema := "tenant_" + tenantID[:8]
		tenantDB, err := db.GetTenantDB(schema)
		if err != nil {
			return echo.NewHTTPError(500, "Tenant DB not found")
		}
		repo := repository.NewConsentRepository(tenantDB)
		svc := services.NewConsentService(repo, auditService)

		c.Set("tenant_id", tenantID)
		c.Set("tenant_db", tenantDB)

		return fn(svc)(c)
	}
}

// GetTenantID retrieves tenant ID from a standard context.Context
func GetTenantID(ctx context.Context) string {
	if v := ctx.Value("tenant_id"); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func GetTenantDB(c echo.Context) *gorm.DB {
	val := c.Get("tenant_db")
	if db, ok := val.(*gorm.DB); ok {
		return db
	}
	return nil
}
