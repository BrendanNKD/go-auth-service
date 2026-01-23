package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-service/middleware"
	"auth-service/utils"

	"github.com/stretchr/testify/assert"
)

type failingWriter struct {
	headers   http.Header
	statusSet int
}

func (f *failingWriter) Header() http.Header {
	if f.headers == nil {
		f.headers = http.Header{}
	}
	return f.headers
}

func (f *failingWriter) WriteHeader(statusCode int) {
	f.statusSet = statusCode
}

func (f *failingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write error")
}

func TestJWKSHandlerSuccess(t *testing.T) {
	cfg := configForTests()
	handler := NewAuthHandler(cfg, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	err := handler.JWKSHandler(rec, req)
	assert.NoError(t, err)

	var response utils.JWKS
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	if assert.Len(t, response.Keys, 1) {
		assert.Equal(t, "RSA", response.Keys[0].Kty)
		assert.Equal(t, cfg.Auth.AccessTokenKeyID, response.Keys[0].Kid)
	}
}

func TestJWKSHandlerEncodeError(t *testing.T) {
	cfg := configForTests()
	handler := NewAuthHandler(cfg, nil)

	writer := &failingWriter{}
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	err := handler.JWKSHandler(writer, req)
	assert.Error(t, err)

	appErr, ok := err.(*middleware.AppError)
	if assert.True(t, ok) {
		assert.Equal(t, http.StatusInternalServerError, appErr.Status)
	}
}
