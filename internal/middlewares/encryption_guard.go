// middlewares/encryption_ready.go
package middlewares

import (
	"consultrnr/consent-manager/pkg/encryption"
	"net/http"

	"github.com/labstack/echo/v4"
)

// RequireEncryptionReady blocks the request if the encryption system is not ready.
func RequireEncryptionReady() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !encryption.IsReady() {
				return echo.NewHTTPError(http.StatusInternalServerError, "Encryption system not initialized")
			}
			return next(c)
		}
	}
}
