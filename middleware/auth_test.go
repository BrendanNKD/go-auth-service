package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-service/config"
	"auth-service/utils"

	"github.com/stretchr/testify/assert"
)

func testMiddlewareConfig() config.Config {
	return config.Config{
		Auth: config.AuthConfig{
			AccessTokenSecret: []byte("secret"),
			AccessCookieName:  "access_token",
		},
	}
}

func TestAuthMiddlewareMissingToken(t *testing.T) {
	handler := AuthMiddleware(testMiddlewareConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "No token provided")
}

func TestAuthMiddlewareInvalidToken(t *testing.T) {
	handler := AuthMiddleware(testMiddlewareConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.value")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Invalid or expired token")
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	cfg := testMiddlewareConfig()
	claims := utils.Claims{Username: "user", Role: "admin"}
	token, err := utils.GenerateToken(claims, time.Minute, "issuer", cfg.Auth.AccessTokenSecret)
	assert.NoError(t, err)

	handler := AuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxClaims, ok := ClaimsFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "user", ctxClaims.Username)
		assert.Equal(t, "admin", ctxClaims.Role)
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.AccessCookieName, Value: token})
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRoleMiddleware(t *testing.T) {
	handler := RoleMiddleware([]string{"admin"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	claims := &utils.Claims{Username: "user", Role: "user"}
	req = req.WithContext(ContextWithClaims(req.Context(), claims))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	claims.Role = "admin"
	req = req.WithContext(ContextWithClaims(req.Context(), claims))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTokenFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Equal(t, "", tokenFromRequest(req, "access_token"))

	req.Header.Set("Authorization", "Bearer header-token")
	assert.Equal(t, "header-token", tokenFromRequest(req, "access_token"))

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "cookie-token"})
	assert.Equal(t, "cookie-token", tokenFromRequest(req, "access_token"))
}

func TestContains(t *testing.T) {
	assert.True(t, contains([]string{"a", "b"}, "a"))
	assert.False(t, contains([]string{"a", "b"}, "c"))
}
