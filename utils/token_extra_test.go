package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestParseTokenInvalidSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	claims := Claims{Username: "user", Role: "admin"}
	token, err := GenerateAccessToken(claims, time.Minute, "issuer", "kid", privateKey)
	assert.NoError(t, err)

	_, err = ParseAccessToken(token, &otherKey.PublicKey)
	assert.Error(t, err)
}

func TestParseTokenInvalidMethod(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	now := time.Now()
	claims := Claims{
		Username: "user",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signed, err := token.SignedString([]byte("secret"))
	assert.NoError(t, err)

	_, err = ParseAccessToken(signed, &privateKey.PublicKey)
	assert.Error(t, err)
}

func TestParseTokenInvalidFlag(t *testing.T) {
	originalParse := parseTokenWithClaims
	parseTokenWithClaims = func(tokenStr string, claims *Claims, publicKey *rsa.PublicKey) (*jwt.Token, error) {
		return &jwt.Token{Valid: false}, nil
	}
	defer func() { parseTokenWithClaims = originalParse }()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	_, err = ParseAccessToken("token", &privateKey.PublicKey)
	assert.Error(t, err)
}
