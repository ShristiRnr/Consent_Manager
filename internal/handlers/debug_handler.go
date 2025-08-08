package handlers

import (
	"net/http"
	"os"

	"consultrnr/consent-manager/pkg/encryption"
	"github.com/labstack/echo/v4"
)

type DecryptRequest struct {
	CipherText string `json:"cipherText"`
}

type DecryptResponse struct {
	PlainText string `json:"plainText"`
}

// ⚠️ INTERNAL ONLY: POST /internal/debug/decrypt
func DecryptDebugHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		// Secure this endpoint
		token := c.Request().Header.Get("X-Debug-Token")
		if token != os.Getenv("DEBUG_ADMIN_SECRET") {
			return echo.NewHTTPError(http.StatusUnauthorized, "unauthorized")
		}

		var req DecryptRequest
		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid payload")
		}

		plain, err := encryption.Decrypt(req.CipherText)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "decryption error")
		}

		return c.JSON(http.StatusOK, DecryptResponse{
			PlainText: plain,
		})
	}
}
