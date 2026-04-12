package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appconfig "auth-service/config"

	"github.com/stretchr/testify/assert"
)

type mockClient struct {
	setFn  func(ctx context.Context, key, value string, ttl time.Duration) error
	getFn  func(ctx context.Context, key string) (string, bool, error)
	delFn  func(ctx context.Context, keys []string) error
	closed bool
}

func (m *mockClient) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if m.setFn != nil {
		return m.setFn(ctx, key, value, ttl)
	}
	return nil
}

func (m *mockClient) Get(ctx context.Context, key string) (string, bool, error) {
	if m.getFn != nil {
		return m.getFn(ctx, key)
	}
	return "", false, nil
}

func (m *mockClient) Del(ctx context.Context, keys []string) error {
	if m.delFn != nil {
		return m.delFn(ctx, keys)
	}
	return nil
}

func (m *mockClient) Close() error {
	m.closed = true
	return nil
}

func newTestStore(client *mockClient) *ValkeyStore {
	return &ValkeyStore{client: client, prefix: "test"}
}

func TestValkeyStoreOperations(t *testing.T) {
	metadataJSON := `{"session_id":"session","username":"user","role":"role","issued_at":"2024-01-01T00:00:00Z"}`
	sessionJSON := `{"current_token_hash":"hash","username":"user","role":"role","issued_at":"2024-01-01T00:00:00Z"}`

	mock := &mockClient{
		setFn: func(ctx context.Context, key, value string, ttl time.Duration) error {
			return nil
		},
		getFn: func(ctx context.Context, key string) (string, bool, error) {
			switch {
			case strings.Contains(key, ":token:"):
				return metadataJSON, true, nil
			case strings.Contains(key, ":session:"):
				return sessionJSON, true, nil
			case strings.Contains(key, ":revoked:"):
				return "session-1", true, nil
			default:
				return "", false, nil
			}
		},
		delFn: func(ctx context.Context, keys []string) error {
			return nil
		},
	}

	store := newTestStore(mock)

	err := store.SaveToken(context.Background(), "token-hash", RefreshTokenMetadata{
		SessionID: "session",
		Username:  "user",
		Role:      "role",
		IssuedAt:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}, time.Second)
	assert.NoError(t, err)

	_, found, err := store.GetToken(context.Background(), "token-hash")
	assert.NoError(t, err)
	assert.True(t, found)

	err = store.SaveSession(context.Background(), "session-1", RefreshSession{
		CurrentTokenHash: "hash",
		Username:         "user",
		Role:             "role",
		IssuedAt:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}, time.Second)
	assert.NoError(t, err)

	_, found, err = store.GetSession(context.Background(), "session-1")
	assert.NoError(t, err)
	assert.True(t, found)

	err = store.MarkRevoked(context.Background(), "token-hash", "session-1", time.Second)
	assert.NoError(t, err)

	sessionID, revoked, err := store.IsRevoked(context.Background(), "token-hash")
	assert.NoError(t, err)
	assert.True(t, revoked)
	assert.Equal(t, "session-1", sessionID)

	err = store.RevokeToken(context.Background(), "token-hash")
	assert.NoError(t, err)

	err = store.RevokeSession(context.Background(), "session-1")
	assert.NoError(t, err)
}

func TestNewValkeyStoreError(t *testing.T) {
	original := newValkeyClient
	newValkeyClient = func(cfg appconfig.ValkeyConfig) (valkeyClient, error) {
		return nil, errors.New("connect failed")
	}
	defer func() { newValkeyClient = original }()

	_, err := NewValkeyStore(appconfig.ValkeyConfig{Addr: "localhost:6379", Prefix: "test"})
	assert.Error(t, err)
}

func TestNewValkeyStoreSuccess(t *testing.T) {
	mock := &mockClient{}
	original := newValkeyClient
	newValkeyClient = func(cfg appconfig.ValkeyConfig) (valkeyClient, error) {
		return mock, nil
	}
	defer func() { newValkeyClient = original }()

	store, err := NewValkeyStore(appconfig.ValkeyConfig{Addr: "localhost:6379", Prefix: "test"})
	assert.NoError(t, err)
	assert.NotNil(t, store)
}

func TestValkeyStoreGetTokenInvalidJSON(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (string, bool, error) {
			return "invalid", true, nil
		},
	}
	store := newTestStore(mock)
	_, _, err := store.GetToken(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreGetSessionInvalidJSON(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (string, bool, error) {
			return "invalid", true, nil
		},
	}
	store := newTestStore(mock)
	_, _, err := store.GetSession(context.Background(), "session")
	assert.Error(t, err)
}

func TestValkeyStoreGetTokenEmptyResponse(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (string, bool, error) {
			return "", false, nil
		},
	}
	store := newTestStore(mock)
	_, found, err := store.GetToken(context.Background(), "token")
	assert.NoError(t, err)
	assert.False(t, found)
}

func TestValkeyStoreGetSessionEmptyResponse(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (string, bool, error) {
			return "", false, nil
		},
	}
	store := newTestStore(mock)
	_, found, err := store.GetSession(context.Background(), "session")
	assert.NoError(t, err)
	assert.False(t, found)
}

func TestValkeyStoreIsRevokedEmptyResponse(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (string, bool, error) {
			return "", false, nil
		},
	}
	store := newTestStore(mock)
	_, revoked, err := store.IsRevoked(context.Background(), "token")
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestValkeyStoreGetTokenError(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (string, bool, error) {
			return "", false, errors.New("get error")
		},
	}
	store := newTestStore(mock)
	_, _, err := store.GetToken(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreGetSessionError(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (string, bool, error) {
			return "", false, errors.New("get error")
		},
	}
	store := newTestStore(mock)
	_, _, err := store.GetSession(context.Background(), "session")
	assert.Error(t, err)
}

func TestValkeyStoreIsRevokedError(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (string, bool, error) {
			return "", false, errors.New("get error")
		},
	}
	store := newTestStore(mock)
	_, _, err := store.IsRevoked(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreSaveTokenMarshalError(t *testing.T) {
	originalMarshal := jsonMarshal
	jsonMarshal = func(v interface{}) ([]byte, error) {
		return nil, errors.New("marshal error")
	}
	defer func() { jsonMarshal = originalMarshal }()

	store := newTestStore(&mockClient{})
	err := store.SaveToken(context.Background(), "token", RefreshTokenMetadata{}, time.Second)
	assert.Error(t, err)
}

func TestValkeyStoreSaveTokenSetError(t *testing.T) {
	mock := &mockClient{
		setFn: func(ctx context.Context, key, value string, ttl time.Duration) error {
			return errors.New("set error")
		},
	}
	store := newTestStore(mock)
	err := store.SaveToken(context.Background(), "token", RefreshTokenMetadata{}, time.Second)
	assert.Error(t, err)
}

func TestValkeyStoreSaveSessionMarshalError(t *testing.T) {
	originalMarshal := jsonMarshal
	jsonMarshal = func(v interface{}) ([]byte, error) {
		return nil, errors.New("marshal error")
	}
	defer func() { jsonMarshal = originalMarshal }()

	store := newTestStore(&mockClient{})
	err := store.SaveSession(context.Background(), "session", RefreshSession{}, time.Second)
	assert.Error(t, err)
}

func TestValkeyStoreSaveSessionSetError(t *testing.T) {
	mock := &mockClient{
		setFn: func(ctx context.Context, key, value string, ttl time.Duration) error {
			return errors.New("set error")
		},
	}
	store := newTestStore(mock)
	err := store.SaveSession(context.Background(), "session", RefreshSession{}, time.Second)
	assert.Error(t, err)
}

func TestValkeyStoreMarkRevokedError(t *testing.T) {
	mock := &mockClient{
		setFn: func(ctx context.Context, key, value string, ttl time.Duration) error {
			return errors.New("set error")
		},
	}
	store := newTestStore(mock)
	err := store.MarkRevoked(context.Background(), "token", "session", time.Second)
	assert.Error(t, err)
}

func TestValkeyStoreRevokeTokenError(t *testing.T) {
	mock := &mockClient{
		delFn: func(ctx context.Context, keys []string) error {
			return errors.New("del error")
		},
	}
	store := newTestStore(mock)
	err := store.RevokeToken(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreRevokeSessionError(t *testing.T) {
	mock := &mockClient{
		delFn: func(ctx context.Context, keys []string) error {
			return errors.New("del error")
		},
	}
	store := newTestStore(mock)
	err := store.RevokeSession(context.Background(), "session")
	assert.Error(t, err)
}

func TestValkeyStoreClose(t *testing.T) {
	mock := &mockClient{}
	store := newTestStore(mock)
	err := store.Close()
	assert.NoError(t, err)
	assert.True(t, mock.closed)
}

func TestHostFromAddr(t *testing.T) {
	assert.Equal(t, "localhost", hostFromAddr("localhost:6379"))
	assert.Equal(t, "127.0.0.1", hostFromAddr("127.0.0.1:6379"))
	assert.Equal(t, "myhost", hostFromAddr("myhost"))
}

func TestPortFromAddr(t *testing.T) {
	assert.Equal(t, 6379, portFromAddr("localhost:6379"))
	assert.Equal(t, 6380, portFromAddr("localhost:6380"))
	assert.Equal(t, 6379, portFromAddr("myhost"))
}
