package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appconfig "auth-service/config"

	"github.com/valkey-io/valkey-glide/go/v2/models"
	"github.com/valkey-io/valkey-glide/go/v2/options"

	"github.com/stretchr/testify/assert"
)

type mockClient struct {
	setWithOptionsFn func(ctx context.Context, key, value string, opts options.SetOptions) (models.Result[string], error)
	getFn            func(ctx context.Context, key string) (models.Result[string], error)
	delFn            func(ctx context.Context, keys []string) (int64, error)
	closed           bool
}

func (m *mockClient) SetWithOptions(ctx context.Context, key, value string, opts options.SetOptions) (models.Result[string], error) {
	if m.setWithOptionsFn != nil {
		return m.setWithOptionsFn(ctx, key, value, opts)
	}
	return models.CreateStringResult("OK"), nil
}

func (m *mockClient) Get(ctx context.Context, key string) (models.Result[string], error) {
	if m.getFn != nil {
		return m.getFn(ctx, key)
	}
	return models.CreateNilStringResult(), nil
}

func (m *mockClient) Del(ctx context.Context, keys []string) (int64, error) {
	if m.delFn != nil {
		return m.delFn(ctx, keys)
	}
	return 1, nil
}

func (m *mockClient) Close() {
	m.closed = true
}

func newTestStore(client *mockClient) *ValkeyStore {
	return &ValkeyStore{client: client, prefix: "test"}
}

func TestValkeyStoreOperations(t *testing.T) {
	metadataJSON := `{"session_id":"session","username":"user","role":"role","issued_at":"2024-01-01T00:00:00Z"}`
	sessionJSON := `{"current_token_hash":"hash","username":"user","role":"role","issued_at":"2024-01-01T00:00:00Z"}`

	mock := &mockClient{
		setWithOptionsFn: func(ctx context.Context, key, value string, opts options.SetOptions) (models.Result[string], error) {
			return models.CreateStringResult("OK"), nil
		},
		getFn: func(ctx context.Context, key string) (models.Result[string], error) {
			switch {
			case strings.Contains(key, ":token:"):
				return models.CreateStringResult(metadataJSON), nil
			case strings.Contains(key, ":session:"):
				return models.CreateStringResult(sessionJSON), nil
			case strings.Contains(key, ":revoked:"):
				return models.CreateStringResult("session-1"), nil
			default:
				return models.CreateNilStringResult(), nil
			}
		},
		delFn: func(ctx context.Context, keys []string) (int64, error) {
			return 1, nil
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
	original := newGlideClient
	newGlideClient = func(cfg appconfig.ValkeyConfig) (valkeyClient, error) {
		return nil, errors.New("connect failed")
	}
	defer func() { newGlideClient = original }()

	_, err := NewValkeyStore(appconfig.ValkeyConfig{Addr: "localhost:6379", Prefix: "test"})
	assert.Error(t, err)
}

func TestNewValkeyStoreSuccess(t *testing.T) {
	mock := &mockClient{}
	original := newGlideClient
	newGlideClient = func(cfg appconfig.ValkeyConfig) (valkeyClient, error) {
		return mock, nil
	}
	defer func() { newGlideClient = original }()

	store, err := NewValkeyStore(appconfig.ValkeyConfig{Addr: "localhost:6379", Prefix: "test"})
	assert.NoError(t, err)
	assert.NotNil(t, store)
}

func TestValkeyStoreGetTokenInvalidJSON(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (models.Result[string], error) {
			return models.CreateStringResult("invalid"), nil
		},
	}
	store := newTestStore(mock)
	_, _, err := store.GetToken(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreGetSessionInvalidJSON(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (models.Result[string], error) {
			return models.CreateStringResult("invalid"), nil
		},
	}
	store := newTestStore(mock)
	_, _, err := store.GetSession(context.Background(), "session")
	assert.Error(t, err)
}

func TestValkeyStoreGetTokenEmptyResponse(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (models.Result[string], error) {
			return models.CreateNilStringResult(), nil
		},
	}
	store := newTestStore(mock)
	_, found, err := store.GetToken(context.Background(), "token")
	assert.NoError(t, err)
	assert.False(t, found)
}

func TestValkeyStoreGetSessionEmptyResponse(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (models.Result[string], error) {
			return models.CreateNilStringResult(), nil
		},
	}
	store := newTestStore(mock)
	_, found, err := store.GetSession(context.Background(), "session")
	assert.NoError(t, err)
	assert.False(t, found)
}

func TestValkeyStoreIsRevokedEmptyResponse(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (models.Result[string], error) {
			return models.CreateNilStringResult(), nil
		},
	}
	store := newTestStore(mock)
	_, revoked, err := store.IsRevoked(context.Background(), "token")
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestValkeyStoreGetTokenError(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (models.Result[string], error) {
			return models.CreateNilStringResult(), errors.New("get error")
		},
	}
	store := newTestStore(mock)
	_, _, err := store.GetToken(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreGetSessionError(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (models.Result[string], error) {
			return models.CreateNilStringResult(), errors.New("get error")
		},
	}
	store := newTestStore(mock)
	_, _, err := store.GetSession(context.Background(), "session")
	assert.Error(t, err)
}

func TestValkeyStoreIsRevokedError(t *testing.T) {
	mock := &mockClient{
		getFn: func(ctx context.Context, key string) (models.Result[string], error) {
			return models.CreateNilStringResult(), errors.New("get error")
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
		setWithOptionsFn: func(ctx context.Context, key, value string, opts options.SetOptions) (models.Result[string], error) {
			return models.CreateNilStringResult(), errors.New("set error")
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
		setWithOptionsFn: func(ctx context.Context, key, value string, opts options.SetOptions) (models.Result[string], error) {
			return models.CreateNilStringResult(), errors.New("set error")
		},
	}
	store := newTestStore(mock)
	err := store.SaveSession(context.Background(), "session", RefreshSession{}, time.Second)
	assert.Error(t, err)
}

func TestValkeyStoreMarkRevokedError(t *testing.T) {
	mock := &mockClient{
		setWithOptionsFn: func(ctx context.Context, key, value string, opts options.SetOptions) (models.Result[string], error) {
			return models.CreateNilStringResult(), errors.New("set error")
		},
	}
	store := newTestStore(mock)
	err := store.MarkRevoked(context.Background(), "token", "session", time.Second)
	assert.Error(t, err)
}

func TestValkeyStoreRevokeTokenError(t *testing.T) {
	mock := &mockClient{
		delFn: func(ctx context.Context, keys []string) (int64, error) {
			return 0, errors.New("del error")
		},
	}
	store := newTestStore(mock)
	err := store.RevokeToken(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreRevokeSessionError(t *testing.T) {
	mock := &mockClient{
		delFn: func(ctx context.Context, keys []string) (int64, error) {
			return 0, errors.New("del error")
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
