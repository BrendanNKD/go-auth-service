package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	appconfig "auth-service/config"

	glide "github.com/valkey-io/valkey-glide/go/v2"
	"github.com/valkey-io/valkey-glide/go/v2/config"
	"github.com/valkey-io/valkey-glide/go/v2/models"
	"github.com/valkey-io/valkey-glide/go/v2/options"
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

// valkeyClient defines the subset of the GLIDE client used by ValkeyStore.
type valkeyClient interface {
	SetWithOptions(ctx context.Context, key string, value string, opts options.SetOptions) (models.Result[string], error)
	Get(ctx context.Context, key string) (models.Result[string], error)
	Del(ctx context.Context, keys []string) (int64, error)
	Close()
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

// newGlideClient creates a real GLIDE client. Replaced in tests.
var newGlideClient = func(cfg appconfig.ValkeyConfig) (valkeyClient, error) {
	glideConfig := config.NewClientConfiguration().
		WithAddress(&config.NodeAddress{Host: hostFromAddr(cfg.Addr), Port: portFromAddr(cfg.Addr)}).
		WithDatabaseId(cfg.DB)

	if cfg.Password != "" {
		glideConfig.WithCredentials(config.NewServerCredentialsWithDefaultUsername(cfg.Password))
	}

	if cfg.UseTLS {
		glideConfig.WithUseTLS(true)
	}

	client, err := glide.NewClient(glideConfig)
	if err != nil {
		return nil, fmt.Errorf("valkey glide connect failed: %w", err)
	}
	return client, nil
}

func NewValkeyStore(cfg appconfig.ValkeyConfig) (*ValkeyStore, error) {
	client, err := newGlideClient(cfg)
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
	opts := *options.NewSetOptions().SetExpiry(options.NewExpiryIn(ttl))
	_, err = v.client.SetWithOptions(ctx, v.tokenKey(tokenHash), string(payload), opts)
	return err
}

func (v *ValkeyStore) GetToken(ctx context.Context, tokenHash string) (RefreshTokenMetadata, bool, error) {
	result, err := v.client.Get(ctx, v.tokenKey(tokenHash))
	if err != nil {
		return RefreshTokenMetadata{}, false, err
	}
	if result.IsNil() {
		return RefreshTokenMetadata{}, false, nil
	}
	var metadata RefreshTokenMetadata
	if err := jsonUnmarshal([]byte(result.Value()), &metadata); err != nil {
		return RefreshTokenMetadata{}, false, err
	}
	return metadata, true, nil
}

func (v *ValkeyStore) RevokeToken(ctx context.Context, tokenHash string) error {
	_, err := v.client.Del(ctx, []string{v.tokenKey(tokenHash)})
	return err
}

func (v *ValkeyStore) SaveSession(ctx context.Context, sessionID string, session RefreshSession, ttl time.Duration) error {
	payload, err := jsonMarshal(session)
	if err != nil {
		return err
	}
	opts := *options.NewSetOptions().SetExpiry(options.NewExpiryIn(ttl))
	_, err = v.client.SetWithOptions(ctx, v.sessionKey(sessionID), string(payload), opts)
	return err
}

func (v *ValkeyStore) GetSession(ctx context.Context, sessionID string) (RefreshSession, bool, error) {
	result, err := v.client.Get(ctx, v.sessionKey(sessionID))
	if err != nil {
		return RefreshSession{}, false, err
	}
	if result.IsNil() {
		return RefreshSession{}, false, nil
	}
	var session RefreshSession
	if err := jsonUnmarshal([]byte(result.Value()), &session); err != nil {
		return RefreshSession{}, false, err
	}
	return session, true, nil
}

func (v *ValkeyStore) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := v.client.Del(ctx, []string{v.sessionKey(sessionID)})
	return err
}

func (v *ValkeyStore) MarkRevoked(ctx context.Context, tokenHash, sessionID string, ttl time.Duration) error {
	opts := *options.NewSetOptions().SetExpiry(options.NewExpiryIn(ttl))
	_, err := v.client.SetWithOptions(ctx, v.revokedKey(tokenHash), sessionID, opts)
	return err
}

func (v *ValkeyStore) IsRevoked(ctx context.Context, tokenHash string) (string, bool, error) {
	result, err := v.client.Get(ctx, v.revokedKey(tokenHash))
	if err != nil {
		return "", false, err
	}
	if result.IsNil() {
		return "", false, nil
	}
	return result.Value(), true, nil
}

func (v *ValkeyStore) Close() error {
	v.client.Close()
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
