package utils

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

func NewRSAJWK(publicKey *rsa.PublicKey, keyID string) JWK {
	if publicKey == nil {
		return JWK{}
	}

	e := big.NewInt(int64(publicKey.E))
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: keyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(e.Bytes()),
	}
}
