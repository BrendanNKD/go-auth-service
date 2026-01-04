package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-service/store"
	"auth-service/utils"

	"github.com/stretchr/testify/assert"
)

func TestRefreshHandlerErrors(t *testing.T) {
	cfg := configForTests()
	handler := NewAuthHandler(cfg, &configurableTokenStore{})

	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := executeRequest(handler.RefreshHandler, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: "invalid"})
	rec = executeRequest(handler.RefreshHandler, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	validToken := "valid-refresh"
	refreshHash := utils.HashRefreshToken(validToken)
	handler = NewAuthHandler(cfg, &configurableTokenStore{getTokenFound: false})
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: validToken})
	rec = executeRequest(handler.RefreshHandler, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	handler = NewAuthHandler(cfg, &configurableTokenStore{
		getTokenFound:   true,
		getSessionFound: true,
		getToken: store.RefreshTokenMetadata{
			SessionID: "session-id",
			Username:  "user",
			Role:      "role",
			IssuedAt:  time.Now(),
		},
		getSession: store.RefreshSession{
			CurrentTokenHash: refreshHash,
		},
		revokeTokenErr: assert.AnError,
	})
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: validToken})
	rec = executeRequest(handler.RefreshHandler, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestLogoutHandlerInvalidToken(t *testing.T) {
	cfg := configForTests()
	handler := NewAuthHandler(cfg, &configurableTokenStore{})

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: "invalid"})
	rec := executeRequest(handler.LogoutHandler, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
