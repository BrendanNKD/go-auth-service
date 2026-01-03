package routes

import (
	"net/http"

	"auth-service/config"
	"auth-service/handlers"
	"auth-service/middleware"

	"github.com/gorilla/mux"
)

func SetupRoutes(cfg config.Config, authHandler *handlers.AuthHandler) *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/register", middleware.ErrorHandler(authHandler.RegisterHandler)).Methods("POST")
	router.HandleFunc("/login", middleware.ErrorHandler(authHandler.LoginHandler)).Methods("POST")
	router.HandleFunc("/refresh", middleware.ErrorHandler(authHandler.RefreshHandler)).Methods("POST")
	router.HandleFunc("/logout", middleware.ErrorHandler(authHandler.LogoutHandler)).Methods("POST")
	router.Handle("/authenticate", middleware.AuthMiddleware(cfg)(middleware.ErrorHandler(authHandler.AuthenticateHandler))).Methods("GET")
	router.HandleFunc("/health", handlers.HealthHandler).Methods("GET")

	return router
}
