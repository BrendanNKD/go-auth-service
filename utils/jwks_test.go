package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRSAJWKNilKey(t *testing.T) {
	assert.Equal(t, JWK{}, NewRSAJWK(nil, "kid"))
}

func TestNewRSAJWK(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	jwk := NewRSAJWK(&privateKey.PublicKey, "kid")
	assert.Equal(t, "RSA", jwk.Kty)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "RS256", jwk.Alg)
	assert.Equal(t, "kid", jwk.Kid)

	expectedN := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())
	e := big.NewInt(int64(privateKey.PublicKey.E))
	expectedE := base64.RawURLEncoding.EncodeToString(e.Bytes())

	assert.Equal(t, expectedN, jwk.N)
	assert.Equal(t, expectedE, jwk.E)
}
