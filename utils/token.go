package utils

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Claims defines the custom JWT claims, including a Role field.
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

var parseTokenWithClaims = func(tokenStr string, claims *Claims, publicKey *rsa.PublicKey) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}))
	return parser.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
}

// GenerateAccessToken creates a signed JWT for the provided claims.
func GenerateAccessToken(claims Claims, ttl time.Duration, issuer, keyID string, privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims.Issuer = issuer
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.NotBefore = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(ttl))

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if keyID != "" {
		token.Header["kid"] = keyID
	}
	return token.SignedString(privateKey)
}

// ParseAccessToken validates a token and returns its claims if valid.
func ParseAccessToken(tokenStr string, publicKey *rsa.PublicKey) (*Claims, error) {
	claims := &Claims{}
	token, err := parseTokenWithClaims(tokenStr, claims, publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}
	return claims, nil
}
