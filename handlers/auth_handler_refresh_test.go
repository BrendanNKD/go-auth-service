package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-service/utils"

	"github.com/stretchr/testify/assert"
)

func TestRefreshHandlerErrors(t *testing.T) {
	cfg := configForTests()
	handler := NewAuthHandler(cfg, &configurableTokenStore{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	handler.RefreshHandler(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: "invalid"})
	handler.RefreshHandler(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	claims := utils.Claims{Username: "user", Role: "role"}
	claims.ID = "refresh-id"
	validToken, err := utils.GenerateToken(claims, time.Minute, cfg.Auth.Issuer, cfg.Auth.RefreshTokenSecret)
	assert.NoError(t, err)

	handler = NewAuthHandler(cfg, &configurableTokenStore{exists: false})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: validToken})
	handler.RefreshHandler(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	handler = NewAuthHandler(cfg, &configurableTokenStore{exists: true, revokeErr: assert.AnError})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: validToken})
	handler.RefreshHandler(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestLogoutHandlerInvalidToken(t *testing.T) {
	cfg := configForTests()
	handler := NewAuthHandler(cfg, &configurableTokenStore{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: "invalid"})
	handler.LogoutHandler(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
