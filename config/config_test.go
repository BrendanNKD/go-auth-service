package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	privateKeyPEM, publicKeyPEM := testKeyPair(t)
	t.Setenv("JWT_ACCESS_PRIVATE_KEY", privateKeyPEM)
	t.Setenv("JWT_ACCESS_PUBLIC_KEY", publicKeyPEM)
	t.Setenv("DB_NAME", "auth")
	t.Setenv("DB_USERNAME", "user")
}

func testKeyPair(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	assert.NoError(t, err)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	return string(privatePEM), string(publicPEM)
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
	t.Setenv("JWT_ACCESS_PRIVATE_KEY", "")
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
	privateKeyPEM, publicKeyPEM := testKeyPair(t)
	t.Setenv("JWT_ACCESS_PRIVATE_KEY", privateKeyPEM)
	t.Setenv("JWT_ACCESS_PUBLIC_KEY", publicKeyPEM)
	t.Setenv("DB_NAME", "")
	t.Setenv("DB_INSTANCE_IDENTIFIER", "")
	t.Setenv("DB_USERNAME", "")
	_, err := Load()
	assert.Error(t, err)
}

func TestLoadHandlesEscapedNewlinesInKeys(t *testing.T) {
	privateKeyPEM, publicKeyPEM := testKeyPair(t)
	t.Setenv("JWT_ACCESS_PRIVATE_KEY", strings.ReplaceAll(privateKeyPEM, "\n", `\n`))
	t.Setenv("JWT_ACCESS_PUBLIC_KEY", strings.ReplaceAll(publicKeyPEM, "\n", `\n`))
	t.Setenv("DB_NAME", "auth")
	t.Setenv("DB_USERNAME", "user")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.NotNil(t, cfg.Auth.AccessTokenPrivateKey)
	assert.NotNil(t, cfg.Auth.AccessTokenPublicKey)
}

func TestLoadHandlesQuotedEscapedNewlinesInKeys(t *testing.T) {
	privateKeyPEM, publicKeyPEM := testKeyPair(t)
	t.Setenv("JWT_ACCESS_PRIVATE_KEY", `"`+strings.ReplaceAll(privateKeyPEM, "\n", `\n`)+`"`)
	t.Setenv("JWT_ACCESS_PUBLIC_KEY", `'`+strings.ReplaceAll(publicKeyPEM, "\n", `\n`)+`'`)
	t.Setenv("DB_NAME", "auth")
	t.Setenv("DB_USERNAME", "user")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.NotNil(t, cfg.Auth.AccessTokenPrivateKey)
	assert.NotNil(t, cfg.Auth.AccessTokenPublicKey)
}
