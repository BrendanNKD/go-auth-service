package handlers

import (
	"bytes"
	"context"
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
	"golang.org/x/crypto/bcrypt"
)

type trackingTokenStore struct {
	revoked bool
}

func (s *trackingTokenStore) SaveToken(ctx context.Context, tokenHash string, metadata store.RefreshTokenMetadata, ttl time.Duration) error {
	return errors.New("save error")
}

func (s *trackingTokenStore) GetToken(ctx context.Context, tokenHash string) (store.RefreshTokenMetadata, bool, error) {
	return store.RefreshTokenMetadata{SessionID: "session-id"}, true, nil
}

func (s *trackingTokenStore) RevokeToken(ctx context.Context, tokenHash string) error {
	s.revoked = true
	return nil
}

func (s *trackingTokenStore) SaveSession(ctx context.Context, sessionID string, session store.RefreshSession, ttl time.Duration) error {
	return nil
}

func (s *trackingTokenStore) GetSession(ctx context.Context, sessionID string) (store.RefreshSession, bool, error) {
	return store.RefreshSession{CurrentTokenHash: utils.HashRefreshToken("refresh-token")}, true, nil
}

func (s *trackingTokenStore) RevokeSession(ctx context.Context, sessionID string) error {
	return nil
}

func (s *trackingTokenStore) MarkRevoked(ctx context.Context, tokenHash, sessionID string, ttl time.Duration) error {
	return nil
}

func (s *trackingTokenStore) IsRevoked(ctx context.Context, tokenHash string) (string, bool, error) {
	return "", false, nil
}

func (s *trackingTokenStore) Close() error {
	return nil
}

func TestLoginHandlerIssueTokensError(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	mock.ExpectQuery(`SELECT u.password_hash, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = \$1`).
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).
			AddRow(string(hashedPassword), "jobseeker"))

	handler := NewAuthHandler(configForTests(), &trackingTokenStore{})
	user := models.User{Username: "testuser", Password: "password"}
	body, _ := json.Marshal(user)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	rec := executeRequest(handler.LoginHandler, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogoutHandlerRevokesToken(t *testing.T) {
	cfg := configForTests()
	store := &trackingTokenStore{}
	handler := NewAuthHandler(cfg, store)

	token := "refresh-token"

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: token})
	rec := executeRequest(handler.LogoutHandler, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, store.revoked)
}
