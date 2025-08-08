package handlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"consultrnr/consent-manager/internal/models"
)

type ConsentHistoryEntry struct {
	TenantID  uuid.UUID        `json:"tenant_id"`
	Action    string           `json:"action"`
	Purposes  []map[string]any `json:"purposes"`
	ChangedBy string           `json:"changed_by"`
	Timestamp time.Time        `json:"timestamp"`
}

func GetAllConsentHistoryHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		// load all consent histories
		var logs []models.ConsentHistory
		if err := db.Table("consent_histories").
			Order("timestamp DESC").
			Find(&logs).
			Error; err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to load consent histories")
		}

		// map to response entries
		entries := make([]ConsentHistoryEntry, 0, len(logs))
		for _, log := range logs {
			var purposes []map[string]any
			// convert []models.Purpose to JSON bytes before unmarshaling into []map[string]any
			data, err := json.Marshal(log.Purposes)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to process purposes")
			}
			_ = json.Unmarshal(data, &purposes)

			entries = append(entries, ConsentHistoryEntry{
				TenantID:  log.TenantID,
				Action:    log.Action,
				Purposes:  purposes,
				ChangedBy: log.ChangedBy,
				Timestamp: log.Timestamp,
			})
		}

		// ensure correct ordering (already DESC in SQL but double-safe)
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Timestamp.After(entries[j].Timestamp)
		})

		return c.JSON(http.StatusOK, entries)
	}
}
