package utils_test

import (
	"testing"
	"time"

	"auth-service/utils"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAndParseToken(t *testing.T) {
	secret := []byte("supersecret")
	claims := utils.Claims{
		Username: "testuser",
		Role:     "admin",
	}
	claims.ID = "token-id"

	token, err := utils.GenerateToken(claims, time.Minute, "test-issuer", secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := utils.ParseToken(token, secret)
	assert.NoError(t, err)
	assert.Equal(t, claims.Username, parsed.Username)
	assert.Equal(t, claims.Role, parsed.Role)
	assert.Equal(t, claims.ID, parsed.ID)
}

func TestParseTokenInvalid(t *testing.T) {
	secret := []byte("supersecret")
	_, err := utils.ParseToken("not.a.valid.token", secret)
	assert.Error(t, err)
}
