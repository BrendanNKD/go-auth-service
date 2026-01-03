package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-service/config"
	"auth-service/db"
	"auth-service/models"
	"auth-service/utils"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

type configurableTokenStore struct {
	saveErr   error
	exists    bool
	existsErr error
	revokeErr error
}

func (s *configurableTokenStore) Save(ctx context.Context, tokenID, username string, ttl time.Duration) error {
	return s.saveErr
}

func (s *configurableTokenStore) Exists(ctx context.Context, tokenID string) (bool, error) {
	return s.exists, s.existsErr
}

func (s *configurableTokenStore) Revoke(ctx context.Context, tokenID string) error {
	return s.revokeErr
}

func (s *configurableTokenStore) Close() error {
	return nil
}

func configForTests() config.Config {
	return config.Config{
		Auth: config.AuthConfig{
			AccessTokenSecret:  []byte("access-secret"),
			RefreshTokenSecret: []byte("refresh-secret"),
			Issuer:             "issuer",
			AccessTokenTTL:     time.Minute,
			RefreshTokenTTL:    time.Hour,
			AccessCookieName:   "access",
			RefreshCookieName:  "refresh",
		},
		Cookie: config.CookieConfig{
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		},
	}
}

func setupMockDB(t *testing.T) (sqlmock.Sqlmock, func()) {
	mockDB, mock, err := sqlmock.New()
	assert.NoError(t, err)
	db.DB = mockDB
	return mock, func() { mockDB.Close() }
}

func TestRegisterHandlerValidationErrors(t *testing.T) {
	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("{"))
	rec := httptest.NewRecorder()
	handler.RegisterHandler(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	body, _ := json.Marshal(models.Users{Username: "", Password: ""})
	req = httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	rec = httptest.NewRecorder()
	handler.RegisterHandler(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRegisterHandlerHashError(t *testing.T) {
	originalGenerate := generateFromPassword
	generateFromPassword = func(password []byte, cost int) ([]byte, error) {
		return nil, errors.New("hash error")
	}
	defer func() { generateFromPassword = originalGenerate }()

	mock, cleanup := setupMockDB(t)
	defer cleanup()

	body, _ := json.Marshal(models.Users{Username: "user", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	handler.RegisterHandler(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterHandlerDBError(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectExec("INSERT INTO users").
		WithArgs("user", sqlmock.AnyArg(), "").
		WillReturnError(errors.New("db error"))

	body, _ := json.Marshal(models.Users{Username: "user", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	handler.RegisterHandler(rec, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginHandlerErrors(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectQuery(`SELECT password, role FROM users WHERE username = \$1`).
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	body, _ := json.Marshal(models.Users{Username: "missing", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	handler.LoginHandler(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	body, _ = json.Marshal(models.Users{})
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	rec = httptest.NewRecorder()
	handler.LoginHandler(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString("{"))
	rec = httptest.NewRecorder()
	handler.LoginHandler(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	mock.ExpectQuery(`SELECT password, role FROM users WHERE username = \$1`).
		WithArgs("error").
		WillReturnError(errors.New("db error"))

	body, _ = json.Marshal(models.Users{Username: "error", Password: "pass"})
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	rec = httptest.NewRecorder()
	handler.LoginHandler(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginHandlerCompareError(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectQuery(`SELECT password, role FROM users WHERE username = \$1`).
		WithArgs("user").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).AddRow("hashed", "role"))

	originalCompare := compareHashAndPassword
	compareHashAndPassword = func(hashedPassword, password []byte) error {
		return errors.New("compare error")
	}
	defer func() { compareHashAndPassword = originalCompare }()

	body, _ := json.Marshal(models.Users{Username: "user", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	handler.LoginHandler(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIssueTokensErrors(t *testing.T) {
	handler := NewAuthHandler(configForTests(), nil)
	err := handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)

	store := &configurableTokenStore{saveErr: errors.New("save error")}
	handler = NewAuthHandler(configForTests(), store)
	err = handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)

	originalRand := randRead
	randRead = func(b []byte) (int, error) {
		return 0, errors.New("rand error")
	}

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{})
	err = handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)
	randRead = originalRand

	originalGenerateToken := generateToken
	generateToken = func(claims utils.Claims, ttl time.Duration, issuer string, secret []byte) (string, error) {
		return "", errors.New("token error")
	}
	defer func() { generateToken = originalGenerateToken }()

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{})
	err = handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)

	call := 0
	generateToken = func(claims utils.Claims, ttl time.Duration, issuer string, secret []byte) (string, error) {
		call++
		if call == 2 {
			return "", errors.New("refresh token error")
		}
		return "token", nil
	}
	handler = NewAuthHandler(configForTests(), &configurableTokenStore{})
	err = handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)
}

func TestValidateRefreshToken(t *testing.T) {
	handler := NewAuthHandler(configForTests(), nil)
	assert.Error(t, handler.validateRefreshToken(context.Background(), "token"))

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{})
	assert.Error(t, handler.validateRefreshToken(context.Background(), ""))

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{exists: false})
	assert.Error(t, handler.validateRefreshToken(context.Background(), "token"))

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{existsErr: errors.New("exists error")})
	assert.Error(t, handler.validateRefreshToken(context.Background(), "token"))

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{exists: true})
	assert.NoError(t, handler.validateRefreshToken(context.Background(), "token"))
}

func TestRotateTokens(t *testing.T) {
	handler := NewAuthHandler(configForTests(), &configurableTokenStore{revokeErr: errors.New("revoke error")})
	claims := &utils.Claims{}
	claims.ID = "id"
	err := handler.rotateTokens(context.Background(), httptest.NewRecorder(), claims)
	assert.Error(t, err)

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{exists: true})
	claims = &utils.Claims{Username: "user", Role: "role"}
	claims.ID = "id"
	err = handler.rotateTokens(context.Background(), httptest.NewRecorder(), claims)
	assert.NoError(t, err)
}

func TestReadCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := readCookie(req, "missing")
	assert.Error(t, err)

	req.AddCookie(&http.Cookie{Name: "token", Value: "value"})
	value, err := readCookie(req, "token")
	assert.NoError(t, err)
	assert.Equal(t, "value", value)
}
