package handlers

import (
	"consultrnr/consent-manager/internal/services"
	"consultrnr/consent-manager/pkg/log"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type NotificationHandler struct {
	Service *services.NotificationService
}

func NewNotificationHandler(svc *services.NotificationService) *NotificationHandler {
	return &NotificationHandler{Service: svc}
}

// GET /api/v1/dashboard/notifications?unread=true&limit=20
func (h *NotificationHandler) List(c echo.Context) error {
	userIDStr := c.Get("user_id").(string)
	if userIDStr == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthenticated")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid user id")
	}

	limitStr := c.QueryParam("limit")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	onlyUnread, _ := strconv.ParseBool(c.QueryParam("unread"))

	list, err := h.Service.List(c.Request().Context(), userID, onlyUnread, limit)
	if err != nil {
		log.Logger.Error().Err(err).Msg("notifications list failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "server error")
	}
	return c.JSON(http.StatusOK, list)
}

// PUT /api/v1/dashboard/notifications/:id/read
func (h *NotificationHandler) MarkRead(c echo.Context) error {
	userIDStr := c.Get("user_id").(string)
	if userIDStr == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthenticated")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid user id")
	}

	notifID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	if err := h.Service.MarkRead(c.Request().Context(), userID, notifID); err != nil {
		log.Logger.Error().Err(err).Msg("mark read failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "server error")
	}
	return c.NoContent(http.StatusNoContent)
}

// PUT /api/v1/dashboard/notifications/read-all
func (h *NotificationHandler) MarkAllRead(c echo.Context) error {
	userIDStr := c.Get("user_id").(string)
	if userIDStr == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "unauthenticated")
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid user id")
	}

	if err := h.Service.MarkAllRead(c.Request().Context(), userID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "server error")
	}
	return c.NoContent(http.StatusNoContent)
}
