package routes_test

import (
	"net/http"
	"testing"

	"auth-service/config"
	"auth-service/handlers"
	"auth-service/routes"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestSetupRoutes(t *testing.T) {
	cfg := config.Config{
		Auth: config.AuthConfig{
			AccessTokenSecret: []byte("test"),
			AccessCookieName:  "access_token",
		},
	}

	authHandler := handlers.NewAuthHandler(cfg, nil)
	router := routes.SetupRoutes(cfg, authHandler)
	assert.IsType(t, &mux.Router{}, router)

	tests := []struct {
		method string
		path   string
	}{
		{"POST", "/register"},
		{"POST", "/login"},
		{"POST", "/logout"},
		{"POST", "/refresh"},
		{"GET", "/authenticate"},
		{"GET", "/health"},
	}

	for _, tt := range tests {
		req, _ := http.NewRequest(tt.method, tt.path, nil)
		match := &mux.RouteMatch{}
		assert.True(t, router.Match(req, match), "Route %s %s not registered", tt.method, tt.path)
	}
}
