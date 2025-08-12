package middlewares

import (
	"net/http"

	"consultrnr/consent-manager/internal/auth"
	"consultrnr/consent-manager/internal/contextkeys"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	apiKeyRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "api_key_requests_total",
			Help: "Number of requests per API key",
		},
		[]string{"tenant_id", "path"},
	)

	apiKeyRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "api_key_request_duration_seconds",
			Help:    "Duration of requests by path and tenant",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"tenant_id", "path"},
	)
)

func init() {
	prometheus.MustRegister(apiKeyRequests)
	prometheus.MustRegister(apiKeyRequestDuration)
}
func PrometheusMetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// extract claims from *http.Request
		claims, _ := r.Context().Value(contextkeys.FiduciaryClaimsKey).(*auth.FiduciaryClaims)
		tenantID := ""
		if claims != nil {
			tenantID = claims.TenantID
		}

		// start timer
		timer := prometheus.NewTimer(
			apiKeyRequestDuration.
				WithLabelValues(tenantID, r.URL.Path),
		)
		defer timer.ObserveDuration()

		// increment counter
		apiKeyRequests.
			WithLabelValues(tenantID, r.URL.Path).
			Inc()

		// call next handler
		next.ServeHTTP(w, r)
	})
}
