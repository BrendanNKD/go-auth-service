package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auth-service/handlers"

	"github.com/stretchr/testify/assert"
)

func TestLoadBalancerDemoHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/lb-demo", nil)
	rec := httptest.NewRecorder()

	handlers.LoadBalancerDemoHandler(rec, req)

	body := rec.Body.String()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.True(t, strings.Contains(body, "/api/v1/debug/instance"))
	assert.True(t, strings.Contains(body, "localStorage"))
	assert.True(t, strings.Contains(body, "Start auto calls"))
}
