package middlewares

import (
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

type limiterEntry struct {
	tokens     int
	lastAccess time.Time
}

var (
	rateLimitStore = make(map[string]*limiterEntry)
	rateLimitLock  sync.Mutex

	requestsPerMinute = 60
)

func RateLimitPerAPIKey() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			apiKey := c.Request().Header.Get(APIKeyHeader)
			if apiKey == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Missing API key")
			}

			now := time.Now()
			rateLimitLock.Lock()
			defer rateLimitLock.Unlock()

			entry, exists := rateLimitStore[apiKey]
			if !exists {
				entry = &limiterEntry{
					tokens:     requestsPerMinute - 1,
					lastAccess: now,
				}
				rateLimitStore[apiKey] = entry
			} else {
				elapsed := now.Sub(entry.lastAccess).Minutes()
				entry.tokens += int(elapsed * float64(requestsPerMinute))
				if entry.tokens > requestsPerMinute {
					entry.tokens = requestsPerMinute
				}
				entry.lastAccess = now

				if entry.tokens <= 0 {
					return echo.NewHTTPError(http.StatusTooManyRequests, "Rate limit exceeded")
				}
				entry.tokens--
			}

			return next(c)
		}
	}
}
