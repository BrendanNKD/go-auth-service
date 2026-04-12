package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	appconfig "auth-service/config"
)

type RefreshTokenStore interface {
	SaveToken(ctx context.Context, tokenHash string, metadata RefreshTokenMetadata, ttl time.Duration) error
	GetToken(ctx context.Context, tokenHash string) (RefreshTokenMetadata, bool, error)
	RevokeToken(ctx context.Context, tokenHash string) error
	SaveSession(ctx context.Context, sessionID string, session RefreshSession, ttl time.Duration) error
	GetSession(ctx context.Context, sessionID string) (RefreshSession, bool, error)
	RevokeSession(ctx context.Context, sessionID string) error
	MarkRevoked(ctx context.Context, tokenHash, sessionID string, ttl time.Duration) error
	IsRevoked(ctx context.Context, tokenHash string) (string, bool, error)
	Close() error
}

var (
	jsonMarshal   = json.Marshal
	jsonUnmarshal = json.Unmarshal
)

// valkeyClient defines the Valkey commands used by ValkeyStore.
type valkeyClient interface {
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, bool, error)
	Del(ctx context.Context, keys []string) error
	Close() error
}

type RefreshTokenMetadata struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
}

type RefreshSession struct {
	CurrentTokenHash string    `json:"current_token_hash"`
	Username         string    `json:"username"`
	Role             string    `json:"role"`
	IssuedAt         time.Time `json:"issued_at"`
}

type ValkeyStore struct {
	client valkeyClient
	prefix string
}

// newValkeyClient creates a real Valkey client. Replaced in tests.
var newValkeyClient = createValkeyClient

func NewValkeyStore(cfg appconfig.ValkeyConfig) (*ValkeyStore, error) {
	client, err := newValkeyClient(cfg)
	if err != nil {
		return nil, err
	}

	return &ValkeyStore{
		client: client,
		prefix: cfg.Prefix,
	}, nil
}

func (v *ValkeyStore) SaveToken(ctx context.Context, tokenHash string, metadata RefreshTokenMetadata, ttl time.Duration) error {
	payload, err := jsonMarshal(metadata)
	if err != nil {
		return err
	}
	return v.client.Set(ctx, v.tokenKey(tokenHash), string(payload), ttl)
}

func (v *ValkeyStore) GetToken(ctx context.Context, tokenHash string) (RefreshTokenMetadata, bool, error) {
	value, found, err := v.client.Get(ctx, v.tokenKey(tokenHash))
	if err != nil {
		return RefreshTokenMetadata{}, false, err
	}
	if !found {
		return RefreshTokenMetadata{}, false, nil
	}
	var metadata RefreshTokenMetadata
	if err := jsonUnmarshal([]byte(value), &metadata); err != nil {
		return RefreshTokenMetadata{}, false, err
	}
	return metadata, true, nil
}

func (v *ValkeyStore) RevokeToken(ctx context.Context, tokenHash string) error {
	return v.client.Del(ctx, []string{v.tokenKey(tokenHash)})
}

func (v *ValkeyStore) SaveSession(ctx context.Context, sessionID string, session RefreshSession, ttl time.Duration) error {
	payload, err := jsonMarshal(session)
	if err != nil {
		return err
	}
	return v.client.Set(ctx, v.sessionKey(sessionID), string(payload), ttl)
}

func (v *ValkeyStore) GetSession(ctx context.Context, sessionID string) (RefreshSession, bool, error) {
	value, found, err := v.client.Get(ctx, v.sessionKey(sessionID))
	if err != nil {
		return RefreshSession{}, false, err
	}
	if !found {
		return RefreshSession{}, false, nil
	}
	var session RefreshSession
	if err := jsonUnmarshal([]byte(value), &session); err != nil {
		return RefreshSession{}, false, err
	}
	return session, true, nil
}

func (v *ValkeyStore) RevokeSession(ctx context.Context, sessionID string) error {
	return v.client.Del(ctx, []string{v.sessionKey(sessionID)})
}

func (v *ValkeyStore) MarkRevoked(ctx context.Context, tokenHash, sessionID string, ttl time.Duration) error {
	return v.client.Set(ctx, v.revokedKey(tokenHash), sessionID, ttl)
}

func (v *ValkeyStore) IsRevoked(ctx context.Context, tokenHash string) (string, bool, error) {
	value, found, err := v.client.Get(ctx, v.revokedKey(tokenHash))
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, nil
	}
	return value, true, nil
}

func (v *ValkeyStore) Close() error {
	if v.client != nil {
		return v.client.Close()
	}
	return nil
}

func (v *ValkeyStore) tokenKey(tokenHash string) string {
	return fmt.Sprintf("%s:token:%s", v.prefix, tokenHash)
}

func (v *ValkeyStore) sessionKey(sessionID string) string {
	return fmt.Sprintf("%s:session:%s", v.prefix, sessionID)
}

func (v *ValkeyStore) revokedKey(tokenHash string) string {
	return fmt.Sprintf("%s:revoked:%s", v.prefix, tokenHash)
}

func hostFromAddr(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

func portFromAddr(addr string) int {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			port := 0
			for _, c := range addr[i+1:] {
				port = port*10 + int(c-'0')
			}
			return port
		}
	}
	return 6379
}
