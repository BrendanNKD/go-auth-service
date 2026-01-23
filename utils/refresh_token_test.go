package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRefreshTokenError(t *testing.T) {
	originalRandRead := randRead
	randRead = func([]byte) (int, error) {
		return 0, errors.New("rand error")
	}
	defer func() { randRead = originalRandRead }()

	token, err := GenerateRefreshToken()
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestGenerateRefreshTokenAndHash(t *testing.T) {
	originalRandRead := randRead
	randRead = func(buffer []byte) (int, error) {
		for i := range buffer {
			buffer[i] = 1
		}
		return len(buffer), nil
	}
	defer func() { randRead = originalRandRead }()

	token, err := GenerateRefreshToken()
	assert.NoError(t, err)
	expected := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	assert.Equal(t, expected, token)

	hash := HashRefreshToken("token")
	sum := sha256.Sum256([]byte("token"))
	assert.Equal(t, hex.EncodeToString(sum[:]), hash)
}
