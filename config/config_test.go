package config

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("JWT_ACCESS_SECRET", "access")
	t.Setenv("JWT_REFRESH_SECRET", "refresh")
	t.Setenv("DB_NAME", "auth")
	t.Setenv("DB_USERNAME", "user")
}

func TestLoadSuccess(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("JWT_ACCESS_TTL", "10m")
	t.Setenv("JWT_REFRESH_TTL", "30m")
	t.Setenv("COOKIE_SAMESITE", "strict")
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://a.com, http://b.com")
	t.Setenv("VALKEY_DB", "2")
	t.Setenv("COOKIE_SECURE", "true")
	t.Setenv("APP_ENV", "prod")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, "prod", cfg.AppEnv)
	assert.Equal(t, "8080", cfg.Port)
	assert.Equal(t, http.SameSiteStrictMode, cfg.Cookie.SameSite)
	assert.Equal(t, []string{"http://a.com", "http://b.com"}, cfg.CORS.AllowedOrigins)
	assert.Equal(t, 2, cfg.Valkey.DB)
	assert.True(t, cfg.Cookie.Secure)
}

func TestLoadMissingSecrets(t *testing.T) {
	t.Setenv("JWT_ACCESS_SECRET", "")
	t.Setenv("JWT_REFRESH_SECRET", "")
	_, err := Load()
	assert.Error(t, err)
}

func TestLoadInvalidAccessTTL(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("JWT_ACCESS_TTL", "not-a-duration")
	_, err := Load()
	assert.Error(t, err)
}

func TestLoadInvalidRefreshTTL(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("JWT_ACCESS_TTL", "10m")
	t.Setenv("JWT_REFRESH_TTL", "not-a-duration")
	_, err := Load()
	assert.Error(t, err)
}

func TestLoadInvalidSameSite(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("COOKIE_SAMESITE", "unknown")
	_, err := Load()
	assert.Error(t, err)
}

func TestLoadInvalidValkeyDB(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("VALKEY_DB", "not-an-int")
	_, err := Load()
	assert.Error(t, err)
}

func TestLoadMissingDatabaseConfig(t *testing.T) {
	t.Setenv("JWT_ACCESS_SECRET", "access")
	t.Setenv("JWT_REFRESH_SECRET", "refresh")
	t.Setenv("DB_NAME", "")
	t.Setenv("DB_INSTANCE_IDENTIFIER", "")
	t.Setenv("DB_USERNAME", "")
	_, err := Load()
	assert.Error(t, err)
}
