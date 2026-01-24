package handlers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-service/models"
	"auth-service/store"
	"auth-service/utils"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

type trackingSessionStore struct {
	getToken        store.RefreshTokenMetadata
	getTokenFound   bool
	getTokenErr     error
	getSession      store.RefreshSession
	getSessionFound bool
	getSessionErr   error
	isRevoked       bool
	isRevokedID     string
	isRevokedErr    error
	revokedToken    bool
	revokedSession  bool
}

func (s *trackingSessionStore) SaveToken(ctx context.Context, tokenHash string, metadata store.RefreshTokenMetadata, ttl time.Duration) error {
	return nil
}

func (s *trackingSessionStore) GetToken(ctx context.Context, tokenHash string) (store.RefreshTokenMetadata, bool, error) {
	return s.getToken, s.getTokenFound, s.getTokenErr
}

func (s *trackingSessionStore) RevokeToken(ctx context.Context, tokenHash string) error {
	s.revokedToken = true
	return nil
}

func (s *trackingSessionStore) SaveSession(ctx context.Context, sessionID string, session store.RefreshSession, ttl time.Duration) error {
	return nil
}

func (s *trackingSessionStore) GetSession(ctx context.Context, sessionID string) (store.RefreshSession, bool, error) {
	return s.getSession, s.getSessionFound, s.getSessionErr
}

func (s *trackingSessionStore) RevokeSession(ctx context.Context, sessionID string) error {
	s.revokedSession = true
	return nil
}

func (s *trackingSessionStore) MarkRevoked(ctx context.Context, tokenHash, sessionID string, ttl time.Duration) error {
	return nil
}

func (s *trackingSessionStore) IsRevoked(ctx context.Context, tokenHash string) (string, bool, error) {
	return s.isRevokedID, s.isRevoked, s.isRevokedErr
}

func (s *trackingSessionStore) Close() error {
	return nil
}

func TestRegisterHandlerBeginError(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectBegin().WillReturnError(errors.New("begin error"))

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	body, _ := json.Marshal(models.User{Username: "user", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	rec := executeRequest(handler.RegisterHandler, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterHandlerRoleNotFound(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM roles WHERE name = \\$1").
		WithArgs("user").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	body, _ := json.Marshal(models.User{Username: "user", Password: "pass", Role: "user"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	rec := executeRequest(handler.RegisterHandler, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterHandlerRoleQueryError(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM roles WHERE name = \\$1").
		WithArgs("user").
		WillReturnError(errors.New("db error"))
	mock.ExpectRollback()

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	body, _ := json.Marshal(models.User{Username: "user", Password: "pass", Role: "user"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	rec := executeRequest(handler.RegisterHandler, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterHandlerCommitError(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM roles WHERE name = \\$1").
		WithArgs("user").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("role-id"))
	mock.ExpectExec("INSERT INTO users").
		WithArgs("user", sqlmock.AnyArg(), sqlmock.AnyArg(), "role-id").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit error"))

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	body, _ := json.Marshal(models.User{Username: "user", Password: "pass", Role: "user"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	rec := executeRequest(handler.RegisterHandler, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterHandlerDefaultRoleName(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM roles WHERE name = \\$1").
		WithArgs("user").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("role-id"))
	mock.ExpectExec("INSERT INTO users").
		WithArgs("user", sqlmock.AnyArg(), sqlmock.AnyArg(), "role-id").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	body, _ := json.Marshal(models.User{Username: "user", Password: "pass", Role: "  "})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	rec := executeRequest(handler.RegisterHandler, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIssueTokensNewTokenIDError(t *testing.T) {
	originalRandRead := randRead
	randRead = func([]byte) (int, error) {
		return 0, errors.New("rand error")
	}
	defer func() { randRead = originalRandRead }()

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	_, err := handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)
}

func TestIssueTokensSaveSessionError(t *testing.T) {
	handler := NewAuthHandler(configForTests(), &configurableTokenStore{saveSessionErr: errors.New("save session error")})
	_, err := handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)
}

func TestValidateRefreshTokenRevoked(t *testing.T) {
	store := &trackingSessionStore{
		isRevoked:       true,
		isRevokedID:     "session",
		getSessionFound: true,
		getSession: store.RefreshSession{
			CurrentTokenHash: "hash",
		},
	}

	handler := NewAuthHandler(configForTests(), store)
	_, err := handler.validateRefreshToken(context.Background(), "hash")
	assert.Error(t, err)
	assert.True(t, store.revokedToken)
	assert.True(t, store.revokedSession)
}

func TestValidateRefreshTokenSessionMismatch(t *testing.T) {
	store := &trackingSessionStore{
		getTokenFound: true,
		getToken: store.RefreshTokenMetadata{
			SessionID: "session",
		},
		getSessionFound: true,
		getSession: store.RefreshSession{
			CurrentTokenHash: "other",
		},
	}

	handler := NewAuthHandler(configForTests(), store)
	_, err := handler.validateRefreshToken(context.Background(), "hash")
	assert.Error(t, err)
	assert.True(t, store.revokedToken)
	assert.True(t, store.revokedSession)
}

func TestValidateRefreshTokenGetSessionError(t *testing.T) {
	store := &trackingSessionStore{
		getTokenFound: true,
		getToken: store.RefreshTokenMetadata{
			SessionID: "session",
		},
		getSessionErr: errors.New("session error"),
	}

	handler := NewAuthHandler(configForTests(), store)
	_, err := handler.validateRefreshToken(context.Background(), "hash")
	assert.Error(t, err)
}

func TestValidateRefreshTokenSessionNotFound(t *testing.T) {
	store := &trackingSessionStore{
		getTokenFound: true,
		getToken: store.RefreshTokenMetadata{
			SessionID: "session",
		},
		getSessionFound: false,
	}

	handler := NewAuthHandler(configForTests(), store)
	_, err := handler.validateRefreshToken(context.Background(), "hash")
	assert.Error(t, err)
}

func TestValidateRefreshTokenRevokedError(t *testing.T) {
	store := &trackingSessionStore{
		isRevokedErr: errors.New("revoked error"),
	}

	handler := NewAuthHandler(configForTests(), store)
	_, err := handler.validateRefreshToken(context.Background(), "hash")
	assert.Error(t, err)
}

func TestRotateTokensErrors(t *testing.T) {
	cfg := configForTests()

	handler := NewAuthHandler(cfg, &configurableTokenStore{markRevokedErr: errors.New("mark error")})
	_, err := handler.rotateTokens(context.Background(), httptest.NewRecorder(), store.RefreshTokenMetadata{SessionID: "id"}, "hash")
	assert.Error(t, err)

	originalGenerateRefresh := generateRefreshToken
	generateRefreshToken = func() (string, error) {
		return "", errors.New("refresh error")
	}
	handler = NewAuthHandler(cfg, &configurableTokenStore{})
	_, err = handler.rotateTokens(context.Background(), httptest.NewRecorder(), store.RefreshTokenMetadata{SessionID: "id", Username: "user", Role: "role"}, "hash")
	assert.Error(t, err)
	generateRefreshToken = originalGenerateRefresh

	originalGenerateAccess := generateAccessToken
	generateRefreshToken = func() (string, error) {
		return "refresh-token", nil
	}
	generateAccessToken = func(claims utils.Claims, ttl time.Duration, issuer, keyID string, privateKey *rsa.PrivateKey) (string, error) {
		return "", errors.New("access error")
	}
	handler = NewAuthHandler(cfg, &configurableTokenStore{})
	_, err = handler.rotateTokens(context.Background(), httptest.NewRecorder(), store.RefreshTokenMetadata{SessionID: "id", Username: "user", Role: "role"}, "hash")
	assert.Error(t, err)

	generateAccessToken = originalGenerateAccess
	generateRefreshToken = originalGenerateRefresh

	handler = NewAuthHandler(cfg, &configurableTokenStore{saveTokenErr: errors.New("save token error")})
	_, err = handler.rotateTokens(context.Background(), httptest.NewRecorder(), store.RefreshTokenMetadata{SessionID: "id", Username: "user", Role: "role"}, "hash")
	assert.Error(t, err)

	handler = NewAuthHandler(cfg, &configurableTokenStore{saveSessionErr: errors.New("save session error")})
	_, err = handler.rotateTokens(context.Background(), httptest.NewRecorder(), store.RefreshTokenMetadata{SessionID: "id", Username: "user", Role: "role"}, "hash")
	assert.Error(t, err)
}

func TestRevokeSession(t *testing.T) {
	store := &trackingSessionStore{
		getSessionFound: true,
		getSession: store.RefreshSession{
			CurrentTokenHash: "hash",
		},
	}
	handler := NewAuthHandler(configForTests(), store)
	handler.revokeSession(context.Background(), "session")
	assert.True(t, store.revokedToken)
	assert.True(t, store.revokedSession)

	handler = NewAuthHandler(configForTests(), store)
	handler.revokeSession(context.Background(), "")
}

func TestLogoutHandlerRevokedSession(t *testing.T) {
	cfg := configForTests()
	store := &trackingSessionStore{
		getTokenFound: true,
		getToken: store.RefreshTokenMetadata{
			SessionID: "session",
		},
		isRevoked:       true,
		isRevokedID:     "session",
		getSessionFound: true,
		getSession: store.RefreshSession{
			CurrentTokenHash: "hash",
		},
	}

	handler := NewAuthHandler(cfg, store)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: "token"})
	rec := executeRequest(handler.LogoutHandler, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, store.revokedSession)
}
