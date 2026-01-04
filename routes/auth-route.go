package routes

import (
	"auth-service/config"
	"auth-service/handlers"
	"auth-service/middleware"

	"github.com/gorilla/mux"
)

func SetupRoutes(cfg config.Config, authHandler *handlers.AuthHandler) *mux.Router {
	router := mux.NewRouter()

	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	authRouter := apiRouter.PathPrefix("/auth").Subrouter()

	authRouter.HandleFunc("/register", middleware.ErrorHandler(authHandler.RegisterHandler)).Methods("POST")
	authRouter.HandleFunc("/login", middleware.ErrorHandler(authHandler.LoginHandler)).Methods("POST")
	authRouter.HandleFunc("/refresh", middleware.ErrorHandler(authHandler.RefreshHandler)).Methods("POST")
	authRouter.HandleFunc("/logout", middleware.ErrorHandler(authHandler.LogoutHandler)).Methods("POST")
	apiRouter.HandleFunc("/health", handlers.HealthHandler).Methods("GET")

	return router
}
