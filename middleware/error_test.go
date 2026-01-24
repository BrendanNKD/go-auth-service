package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppErrorErrorAndUnwrap(t *testing.T) {
	baseErr := errors.New("root error")
	appErr := &AppError{Status: http.StatusBadRequest, Message: "bad", Err: baseErr}
	assert.Equal(t, baseErr.Error(), appErr.Error())
	assert.ErrorIs(t, appErr, baseErr)

	appErr = &AppError{Status: http.StatusBadRequest, Message: "message"}
	assert.Equal(t, "message", appErr.Error())
}

func TestErrorHandlerAppErrorResponse(t *testing.T) {
	handler := ErrorHandler(func(w http.ResponseWriter, r *http.Request) error {
		return NewAppError(http.StatusBadRequest, "bad request", errors.New("bad"))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var payload map[string]string
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "bad request", payload["error"])
}

func TestErrorHandlerGenericErrorResponse(t *testing.T) {
	handler := ErrorHandler(func(w http.ResponseWriter, r *http.Request) error {
		return errors.New("boom")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var payload map[string]string
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "Internal server error", payload["error"])
}

func TestErrorHandlerRespectsWrittenHeader(t *testing.T) {
	handler := ErrorHandler(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusNoContent)
		return errors.New("ignored")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String())
}

func TestErrorHandlerPanicRecovery(t *testing.T) {
	handler := ErrorHandler(func(w http.ResponseWriter, r *http.Request) error {
		panic("boom")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	var payload map[string]string
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "Internal server error", payload["error"])
}
