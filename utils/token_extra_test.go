package utils

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestParseTokenInvalidSignature(t *testing.T) {
	claims := Claims{Username: "user", Role: "admin"}
	token, err := GenerateToken(claims, time.Minute, "issuer", []byte("secret"))
	assert.NoError(t, err)

	_, err = ParseToken(token, []byte("wrong"))
	assert.Error(t, err)
}

func TestParseTokenInvalidMethod(t *testing.T) {
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

	_, err = ParseToken(signed, []byte("secret"))
	assert.Error(t, err)
}

func TestParseTokenInvalidFlag(t *testing.T) {
	originalParse := parseTokenWithClaims
	parseTokenWithClaims = func(tokenStr string, claims *Claims, secret []byte) (*jwt.Token, error) {
		return &jwt.Token{Valid: false}, nil
	}
	defer func() { parseTokenWithClaims = originalParse }()

	_, err := ParseToken("token", []byte("secret"))
	assert.Error(t, err)
}
