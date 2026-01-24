package middleware

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

type AppHandler func(http.ResponseWriter, *http.Request) error

type AppError struct {
	Status  int
	Message string
	Err     error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Err
}

func NewAppError(status int, message string, err error) *AppError {
	return &AppError{Status: status, Message: message, Err: err}
}

type errorResponse struct {
	Error string `json:"error"`
}

type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if !rw.wroteHeader {
		rw.status = statusCode
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(statusCode)
}

func ErrorHandler(handler AppHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("panic recovered: %v", recovered)
				if !rw.wroteHeader {
					writeErrorResponse(rw, http.StatusInternalServerError, "Internal server error")
				}
			}
		}()

		if err := handler(rw, r); err != nil {
			handleError(rw, r, err)
		}
	}
}

func handleError(w *responseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	message := "Internal server error"

	var appErr *AppError
	if errors.As(err, &appErr) {
		status = appErr.Status
		message = appErr.Message
	}

	if status >= http.StatusInternalServerError {
		log.Printf("request failed: method=%s path=%s status=%d err=%v", r.Method, r.URL.Path, status, err)
	}

	if w.wroteHeader {
		return
	}

	writeErrorResponse(w, status, message)
}

func writeErrorResponse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: message})
}
