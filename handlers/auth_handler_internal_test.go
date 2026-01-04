package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-service/config"
	"auth-service/db"
	"auth-service/middleware"
	"auth-service/models"
	"auth-service/store"
	"auth-service/utils"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

type configurableTokenStore struct {
	saveTokenErr     error
	saveSessionErr   error
	getToken         store.RefreshTokenMetadata
	getTokenFound    bool
	getTokenErr      error
	getSession       store.RefreshSession
	getSessionFound  bool
	getSessionErr    error
	revokeTokenErr   error
	revokeSessionErr error
	markRevokedErr   error
	isRevoked        bool
	isRevokedID      string
	isRevokedErr     error
}

func (s *configurableTokenStore) SaveToken(ctx context.Context, tokenHash string, metadata store.RefreshTokenMetadata, ttl time.Duration) error {
	return s.saveTokenErr
}

func (s *configurableTokenStore) GetToken(ctx context.Context, tokenHash string) (store.RefreshTokenMetadata, bool, error) {
	return s.getToken, s.getTokenFound, s.getTokenErr
}

func (s *configurableTokenStore) RevokeToken(ctx context.Context, tokenHash string) error {
	return s.revokeTokenErr
}

func (s *configurableTokenStore) SaveSession(ctx context.Context, sessionID string, session store.RefreshSession, ttl time.Duration) error {
	return s.saveSessionErr
}

func (s *configurableTokenStore) GetSession(ctx context.Context, sessionID string) (store.RefreshSession, bool, error) {
	return s.getSession, s.getSessionFound, s.getSessionErr
}

func (s *configurableTokenStore) RevokeSession(ctx context.Context, sessionID string) error {
	return s.revokeSessionErr
}

func (s *configurableTokenStore) MarkRevoked(ctx context.Context, tokenHash, sessionID string, ttl time.Duration) error {
	return s.markRevokedErr
}

func (s *configurableTokenStore) IsRevoked(ctx context.Context, tokenHash string) (string, bool, error) {
	return s.isRevokedID, s.isRevoked, s.isRevokedErr
}

func (s *configurableTokenStore) Close() error {
	return nil
}

func configForTests() config.Config {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return config.Config{
		Auth: config.AuthConfig{
			AccessTokenPrivateKey: privateKey,
			AccessTokenPublicKey:  &privateKey.PublicKey,
			AccessTokenKeyID:      "kid",
			Issuer:                "issuer",
			AccessTokenTTL:        time.Minute,
			RefreshTokenTTL:       time.Hour,
			AccessCookieName:      "access",
			RefreshCookieName:     "refresh",
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

func executeRequest(handler func(http.ResponseWriter, *http.Request) error, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	middleware.ErrorHandler(handler).ServeHTTP(rec, req)
	return rec
}

func TestRegisterHandlerValidationErrors(t *testing.T) {
	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("{"))
	rec := executeRequest(handler.RegisterHandler, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	body, _ := json.Marshal(models.User{Username: "", Password: ""})
	req = httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	rec = executeRequest(handler.RegisterHandler, req)
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

	body, _ := json.Marshal(models.User{Username: "user", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	rec := executeRequest(handler.RegisterHandler, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterHandlerDBError(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectQuery("SELECT id FROM roles WHERE name = \\$1").
		WithArgs("user").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("role-id"))
	mock.ExpectExec("INSERT INTO users").
		WithArgs("user", sqlmock.AnyArg(), sqlmock.AnyArg(), "role-id").
		WillReturnError(errors.New("db error"))

	body, _ := json.Marshal(models.User{Username: "user", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	rec := executeRequest(handler.RegisterHandler, req)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginHandlerErrors(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectQuery(`SELECT u.password_hash, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = \$1`).
		WithArgs("missing").
		WillReturnError(sql.ErrNoRows)

	body, _ := json.Marshal(models.User{Username: "missing", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))

	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	rec := executeRequest(handler.LoginHandler, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	body, _ = json.Marshal(models.User{})
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	rec = executeRequest(handler.LoginHandler, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString("{"))
	rec = executeRequest(handler.LoginHandler, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	mock.ExpectQuery(`SELECT u.password_hash, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = \$1`).
		WithArgs("error").
		WillReturnError(errors.New("db error"))

	body, _ = json.Marshal(models.User{Username: "error", Password: "pass"})
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	rec = executeRequest(handler.LoginHandler, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginHandlerCompareError(t *testing.T) {
	mock, cleanup := setupMockDB(t)
	defer cleanup()

	mock.ExpectQuery(`SELECT u.password_hash, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = \$1`).
		WithArgs("user").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).AddRow("hashed", "role"))

	originalCompare := compareHashAndPassword
	compareHashAndPassword = func(hashedPassword, password []byte) error {
		return errors.New("compare error")
	}
	defer func() { compareHashAndPassword = originalCompare }()

	body, _ := json.Marshal(models.User{Username: "user", Password: "pass"})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	handler := NewAuthHandler(configForTests(), &configurableTokenStore{})
	rec := executeRequest(handler.LoginHandler, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIssueTokensErrors(t *testing.T) {
	handler := NewAuthHandler(configForTests(), nil)
	_, err := handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)

	store := &configurableTokenStore{saveTokenErr: errors.New("save error")}
	handler = NewAuthHandler(configForTests(), store)
	_, err = handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)

	originalGenerateToken := generateAccessToken
	generateAccessToken = func(claims utils.Claims, ttl time.Duration, issuer, keyID string, privateKey *rsa.PrivateKey) (string, error) {
		return "", errors.New("token error")
	}
	defer func() { generateAccessToken = originalGenerateToken }()

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{})
	_, err = handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)

	call := 0
	generateAccessToken = func(claims utils.Claims, ttl time.Duration, issuer, keyID string, privateKey *rsa.PrivateKey) (string, error) {
		call++
		return "token", nil
	}
	originalGenerateRefresh := generateRefreshToken
	generateRefreshToken = func() (string, error) {
		if call == 1 {
			return "", errors.New("refresh token error")
		}
		return "refresh-token", nil
	}
	defer func() {
		generateAccessToken = originalGenerateToken
		generateRefreshToken = originalGenerateRefresh
	}()

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{})
	_, err = handler.issueTokens(context.Background(), httptest.NewRecorder(), "user", "role")
	assert.Error(t, err)
}

func TestValidateRefreshToken(t *testing.T) {
	handler := NewAuthHandler(configForTests(), nil)
	_, err := handler.validateRefreshToken(context.Background(), "token")
	assert.Error(t, err)

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{})
	_, err = handler.validateRefreshToken(context.Background(), "")
	assert.Error(t, err)

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{getTokenFound: false})
	_, err = handler.validateRefreshToken(context.Background(), "token")
	assert.Error(t, err)

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{getTokenErr: errors.New("get error")})
	_, err = handler.validateRefreshToken(context.Background(), "token")
	assert.Error(t, err)

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{
		getTokenFound:   true,
		getSessionFound: true,
		getSession: store.RefreshSession{
			CurrentTokenHash: "token",
		},
	})
	_, err = handler.validateRefreshToken(context.Background(), "token")
	assert.NoError(t, err)
}

func TestRotateTokens(t *testing.T) {
	handler := NewAuthHandler(configForTests(), &configurableTokenStore{revokeTokenErr: errors.New("revoke error")})
	_, err := handler.rotateTokens(context.Background(), httptest.NewRecorder(), store.RefreshTokenMetadata{SessionID: "id"}, "hash")
	assert.Error(t, err)

	handler = NewAuthHandler(configForTests(), &configurableTokenStore{})
	_, err = handler.rotateTokens(context.Background(), httptest.NewRecorder(), store.RefreshTokenMetadata{SessionID: "id", Username: "user", Role: "role"}, "hash")
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
