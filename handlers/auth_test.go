package handlers_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-service/config"
	"auth-service/db"
	"auth-service/handlers"
	"auth-service/middleware"
	"auth-service/models"
	"auth-service/store"
	"auth-service/utils"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type stubTokenStore struct {
	tokens   map[string]store.RefreshTokenMetadata
	sessions map[string]store.RefreshSession
}

func newStubTokenStore() *stubTokenStore {
	return &stubTokenStore{
		tokens:   make(map[string]store.RefreshTokenMetadata),
		sessions: make(map[string]store.RefreshSession),
	}
}

func (s *stubTokenStore) SaveToken(_ context.Context, tokenHash string, metadata store.RefreshTokenMetadata, _ time.Duration) error {
	s.tokens[tokenHash] = metadata
	return nil
}

func (s *stubTokenStore) GetToken(_ context.Context, tokenHash string) (store.RefreshTokenMetadata, bool, error) {
	metadata, ok := s.tokens[tokenHash]
	return metadata, ok, nil
}

func (s *stubTokenStore) RevokeToken(_ context.Context, tokenHash string) error {
	delete(s.tokens, tokenHash)
	return nil
}

func (s *stubTokenStore) SaveSession(_ context.Context, sessionID string, session store.RefreshSession, _ time.Duration) error {
	s.sessions[sessionID] = session
	return nil
}

func (s *stubTokenStore) GetSession(_ context.Context, sessionID string) (store.RefreshSession, bool, error) {
	session, ok := s.sessions[sessionID]
	return session, ok, nil
}

func (s *stubTokenStore) RevokeSession(_ context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

func (s *stubTokenStore) MarkRevoked(_ context.Context, tokenHash, sessionID string, _ time.Duration) error {
	return nil
}

func (s *stubTokenStore) IsRevoked(_ context.Context, tokenHash string) (string, bool, error) {
	return "", false, nil
}

func (s *stubTokenStore) Close() error {
	return nil
}

func setupMockDB() (sqlmock.Sqlmock, func()) {
	mockDB, mock, _ := sqlmock.New()
	db.DB = mockDB
	return mock, func() { mockDB.Close() }
}

func testConfig() config.Config {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return config.Config{
		Auth: config.AuthConfig{
			AccessTokenPrivateKey: privateKey,
			AccessTokenPublicKey:  &privateKey.PublicKey,
			AccessTokenKeyID:      "kid",
			Issuer:                "test-issuer",
			AccessTokenTTL:        time.Minute,
			RefreshTokenTTL:       time.Hour,
			AccessCookieName:      "access_token",
			RefreshCookieName:     "refresh_token",
		},
		Cookie: config.CookieConfig{
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		},
	}
}

func executeRequest(handler middleware.AppHandler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	middleware.ErrorHandler(handler).ServeHTTP(rec, req)
	return rec
}

func TestRegisterHandler(t *testing.T) {
	mock, cleanup := setupMockDB()
	defer cleanup()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM roles WHERE name = \\$1").
		WithArgs("jobseeker").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("role-id"))
	mock.ExpectExec("INSERT INTO users").
		WithArgs("testuser", sqlmock.AnyArg(), sqlmock.AnyArg(), "role-id").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	handler := handlers.NewAuthHandler(testConfig(), newStubTokenStore())
	user := models.User{Username: "testuser", Password: "password", Role: "jobseeker"}
	body, err := json.Marshal(user)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
	rec := executeRequest(handler.RegisterHandler, req)
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestRegisterHandler_InvalidJSON(t *testing.T) {
	handler := handlers.NewAuthHandler(testConfig(), newStubTokenStore())
	req := httptest.NewRequest("POST", "/register", bytes.NewBufferString("{invalid-json"))
	rec := executeRequest(handler.RegisterHandler, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestLoginHandler(t *testing.T) {
	mock, cleanup := setupMockDB()
	defer cleanup()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	mock.ExpectQuery(`SELECT u.password_hash, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = \$1`).
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).
			AddRow(string(hashedPassword), "jobseeker"))

	store := newStubTokenStore()
	handler := handlers.NewAuthHandler(testConfig(), store)
	user := models.User{Username: "testuser", Password: "password"}
	body, _ := json.Marshal(user)
	req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	rec := executeRequest(handler.LoginHandler, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	cookies := rec.Result().Cookies()
	assert.NotEmpty(t, cookies)

	var payload map[string]interface{}
	assert.NoError(t, json.NewDecoder(rec.Body).Decode(&payload))
	assert.NotEmpty(t, payload["access_token"])
}

func TestLoginHandler_WrongPassword(t *testing.T) {
	mock, cleanup := setupMockDB()
	defer cleanup()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("different_password"), bcrypt.DefaultCost)
	mock.ExpectQuery(`SELECT u.password_hash, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = \$1`).
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).
			AddRow(string(hashedPassword), "jobseeker"))

	handler := handlers.NewAuthHandler(testConfig(), newStubTokenStore())
	user := models.User{Username: "testuser", Password: "password"}
	body, _ := json.Marshal(user)
	req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	rec := executeRequest(handler.LoginHandler, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRefreshHandler(t *testing.T) {
	mock, cleanup := setupMockDB()
	defer cleanup()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	mock.ExpectQuery(`SELECT u.password_hash, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = \$1`).
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).
			AddRow(string(hashedPassword), "jobseeker"))

	store := newStubTokenStore()
	cfg := testConfig()
	handler := handlers.NewAuthHandler(cfg, store)

	loginBody, _ := json.Marshal(models.User{Username: "testuser", Password: "password"})
	loginReq := httptest.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
	loginRec := executeRequest(handler.LoginHandler, loginReq)
	assert.Equal(t, http.StatusOK, loginRec.Code)

	var refreshCookie *http.Cookie
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == cfg.Auth.RefreshCookieName {
			refreshCookie = cookie
			break
		}
	}
	if assert.NotNil(t, refreshCookie) {
		tokenHash := utils.HashRefreshToken(refreshCookie.Value)
		metadata, found, err := store.GetToken(context.Background(), tokenHash)
		assert.NoError(t, err)
		assert.True(t, found)
		session, found, err := store.GetSession(context.Background(), metadata.SessionID)
		assert.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, tokenHash, session.CurrentTokenHash)

		refreshReq := httptest.NewRequest("POST", "/refresh", nil)
		refreshReq.AddCookie(refreshCookie)
		refreshRec := executeRequest(handler.RefreshHandler, refreshReq)
		assert.Equal(t, http.StatusOK, refreshRec.Code)

		var payload map[string]interface{}
		assert.NoError(t, json.NewDecoder(refreshRec.Body).Decode(&payload))
		assert.NotEmpty(t, payload["access_token"])
	}
}

func TestLogoutHandler(t *testing.T) {
	handler := handlers.NewAuthHandler(testConfig(), newStubTokenStore())
	req := httptest.NewRequest("POST", "/logout", nil)
	rec := executeRequest(handler.LogoutHandler, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
