package handlers_test

import (
	"bytes"
	"context"
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
	"auth-service/utils"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type stubTokenStore struct {
	entries map[string]string
}

func newStubTokenStore() *stubTokenStore {
	return &stubTokenStore{entries: make(map[string]string)}
}

func (s *stubTokenStore) Save(_ context.Context, tokenID, username string, _ time.Duration) error {
	s.entries[tokenID] = username
	return nil
}

func (s *stubTokenStore) Exists(_ context.Context, tokenID string) (bool, error) {
	_, ok := s.entries[tokenID]
	return ok, nil
}

func (s *stubTokenStore) Revoke(_ context.Context, tokenID string) error {
	delete(s.entries, tokenID)
	return nil
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
	return config.Config{
		Auth: config.AuthConfig{
			AccessTokenSecret:  []byte("access-secret"),
			RefreshTokenSecret: []byte("refresh-secret"),
			Issuer:             "test-issuer",
			AccessTokenTTL:     time.Minute,
			RefreshTokenTTL:    time.Hour,
			AccessCookieName:   "access_token",
			RefreshCookieName:  "refresh_token",
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

	mock.ExpectExec("INSERT INTO users").
		WithArgs("testuser", sqlmock.AnyArg(), "jobseeker").
		WillReturnResult(sqlmock.NewResult(1, 1))

	handler := handlers.NewAuthHandler(testConfig(), newStubTokenStore())
	user := models.Users{Username: "testuser", Password: "password", Role: "jobseeker"}
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

	mock.ExpectQuery(`SELECT password, role FROM users WHERE username = \$1`).
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).
			AddRow(string(hashedPassword), "jobseeker"))

	store := newStubTokenStore()
	handler := handlers.NewAuthHandler(testConfig(), store)
	user := models.Users{Username: "testuser", Password: "password"}
	body, _ := json.Marshal(user)
	req := httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	rec := executeRequest(handler.LoginHandler, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	cookies := rec.Result().Cookies()
	assert.NotEmpty(t, cookies)
}

func TestLoginHandler_WrongPassword(t *testing.T) {
	mock, cleanup := setupMockDB()
	defer cleanup()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("different_password"), bcrypt.DefaultCost)
	mock.ExpectQuery(`SELECT password, role FROM users WHERE username = \$1`).
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).
			AddRow(string(hashedPassword), "jobseeker"))

	handler := handlers.NewAuthHandler(testConfig(), newStubTokenStore())
	user := models.Users{Username: "testuser", Password: "password"}
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

	mock.ExpectQuery(`SELECT password, role FROM users WHERE username = \$1`).
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"password", "role"}).
			AddRow(string(hashedPassword), "jobseeker"))

	store := newStubTokenStore()
	cfg := testConfig()
	handler := handlers.NewAuthHandler(cfg, store)

	loginBody, _ := json.Marshal(models.Users{Username: "testuser", Password: "password"})
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
		refreshReq := httptest.NewRequest("POST", "/refresh", nil)
		refreshReq.AddCookie(refreshCookie)
		refreshRec := executeRequest(handler.RefreshHandler, refreshReq)
		assert.Equal(t, http.StatusOK, refreshRec.Code)
	}
}

func TestAuthenticateHandler(t *testing.T) {
	handler := handlers.NewAuthHandler(testConfig(), newStubTokenStore())
	req := httptest.NewRequest("GET", "/authenticate", nil)
	rec := executeRequest(handler.AuthenticateHandler, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	claims := &utils.Claims{Username: "testuser", Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	rec = executeRequest(handler.AuthenticateHandler, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestLogoutHandler(t *testing.T) {
	handler := handlers.NewAuthHandler(testConfig(), newStubTokenStore())
	req := httptest.NewRequest("POST", "/logout", nil)
	rec := executeRequest(handler.LogoutHandler, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
