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
	"auth-service/utils"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type trackingTokenStore struct {
	revoked bool
}

func (s *trackingTokenStore) Save(ctx context.Context, tokenID, username string, ttl time.Duration) error {
	return errors.New("save error")
}

func (s *trackingTokenStore) Exists(ctx context.Context, tokenID string) (bool, error) {
	return true, nil
}

func (s *trackingTokenStore) Revoke(ctx context.Context, tokenID string) error {
	s.revoked = true
	return nil
}

func (s *trackingTokenStore) Close() error {
	return nil
}

func TestLoginHandlerIssueTokensError(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	mock.ExpectQuery(`SELECT password, role FROM users WHERE username = \$1`).
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).
			AddRow(string(hashedPassword), "jobseeker"))

	handler := NewAuthHandler(configForTests(), &trackingTokenStore{})
	user := models.Users{Username: "testuser", Password: "password"}
	body, _ := json.Marshal(user)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	handler.LoginHandler(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogoutHandlerRevokesToken(t *testing.T) {
	cfg := configForTests()
	store := &trackingTokenStore{}
	handler := NewAuthHandler(cfg, store)

	claims := utils.Claims{Username: "user", Role: "role"}
	claims.ID = "refresh-id"
	token, err := utils.GenerateToken(claims, cfg.Auth.RefreshTokenTTL, cfg.Auth.Issuer, cfg.Auth.RefreshTokenSecret)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Auth.RefreshCookieName, Value: token})
	rec := httptest.NewRecorder()

	handler.LogoutHandler(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, store.revoked)
}
