package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/felixge/httpsnoop"
	"go.opentelemetry.io/otel/trace"
)

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		metrics := httpsnoop.CaptureMetrics(next, w, r)
		duration := metrics.Duration
		if duration == 0 {
			duration = time.Since(start)
		}

		span := trace.SpanFromContext(r.Context())
		spanContext := span.SpanContext()
		traceID := spanContext.TraceID().String()
		spanID := spanContext.SpanID().String()

		log.Printf(
			"request method=%s path=%s status=%d duration=%s trace_id=%s span_id=%s",
			r.Method,
			r.URL.Path,
			metrics.Code,
			duration,
			traceID,
			spanID,
		)
	})
}
