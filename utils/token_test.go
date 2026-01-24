package utils_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"auth-service/utils"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAndParseToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	claims := utils.Claims{
		Username: "testuser",
		Role:     "admin",
	}
	claims.ID = "token-id"

	token, err := utils.GenerateAccessToken(claims, time.Minute, "test-issuer", "kid", privateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := utils.ParseAccessToken(token, &privateKey.PublicKey)
	assert.NoError(t, err)
	assert.Equal(t, claims.Username, parsed.Username)
	assert.Equal(t, claims.Role, parsed.Role)
	assert.Equal(t, claims.ID, parsed.ID)
}

func TestParseTokenInvalid(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	_, err = utils.ParseAccessToken("not.a.valid.token", &privateKey.PublicKey)
	assert.Error(t, err)
}
