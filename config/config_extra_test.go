package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnvUsesFallback(t *testing.T) {
	t.Setenv("TEST_ENV", "")
	assert.Equal(t, "fallback", getEnv("TEST_ENV", "fallback"))

	t.Setenv("TEST_ENV", "value")
	assert.Equal(t, "value", getEnv("TEST_ENV", "fallback"))
}

func TestParseCSVTrimsValues(t *testing.T) {
	assert.Equal(t, []string{"a", "b", "c"}, parseCSV("a, b,, ,c"))
}

func TestParseRSAPrivateKeyErrors(t *testing.T) {
	_, err := parseRSAPrivateKey("not-pem")
	assert.Error(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	ecdsaDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	assert.NoError(t, err)
	ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecdsaDER})

	_, err = parseRSAPrivateKey(string(ecdsaPEM))
	assert.Error(t, err)

	invalidPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")})
	_, err = parseRSAPrivateKey(string(invalidPEM))
	assert.Error(t, err)
}

func TestParseRSAPrivateKeyPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	parsed, err := parseRSAPrivateKey(string(privatePEM))
	assert.NoError(t, err)
	assert.Equal(t, key.PublicKey.N, parsed.PublicKey.N)
}

func TestParseRSAPublicKeyErrors(t *testing.T) {
	_, err := parseRSAPublicKey("not-pem")
	assert.Error(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	assert.NoError(t, err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	_, err = parseRSAPublicKey(string(publicPEM))
	assert.Error(t, err)

	invalidPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")})
	_, err = parseRSAPublicKey(string(invalidPEM))
	assert.Error(t, err)
}

func TestLoadUsesInstanceIdentifierAndDefaultSSL(t *testing.T) {
	privateKeyPEM, _ := testKeyPair(t)
	t.Setenv("JWT_ACCESS_PRIVATE_KEY", privateKeyPEM)
	t.Setenv("JWT_ACCESS_PUBLIC_KEY", "")
	t.Setenv("DB_NAME", "")
	t.Setenv("DB_INSTANCE_IDENTIFIER", "instance-id")
	t.Setenv("DB_USERNAME", "user")
	t.Setenv("APP_ENV", "dev")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, "instance-id", cfg.DB.Name)
	assert.Equal(t, "disable", cfg.DB.SSLMode)
	assert.NotNil(t, cfg.Auth.AccessTokenPublicKey)
}

func TestLoadInvalidPublicKey(t *testing.T) {
	privateKeyPEM, _ := testKeyPair(t)
	t.Setenv("JWT_ACCESS_PRIVATE_KEY", privateKeyPEM)
	t.Setenv("JWT_ACCESS_PUBLIC_KEY", "invalid")
	t.Setenv("DB_NAME", "db")
	t.Setenv("DB_USERNAME", "user")

	_, err := Load()
	assert.Error(t, err)
}

func TestLoadInvalidPrivateKey(t *testing.T) {
	t.Setenv("JWT_ACCESS_PRIVATE_KEY", "invalid")
	t.Setenv("DB_NAME", "db")
	t.Setenv("DB_USERNAME", "user")

	_, err := Load()
	assert.Error(t, err)
}
