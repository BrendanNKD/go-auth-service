package main

import (
	"auth-service/config"
	"auth-service/db"
	"auth-service/handlers"
	"auth-service/routes"
	"auth-service/secretmanager" // Ensure this is available in production.
	"auth-service/store"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/joho/godotenv"
)

var (
	loadEnv        = godotenv.Load
	loadConfig     = config.Load
	connectDB      = db.Connect
	newValkeyStore = store.NewValkeyStore
	setupRoutes    = routes.SetupRoutes
	listenAndServe = http.ListenAndServe
	getSecret      = secretmanager.GetSecret
	logFatal       = log.Fatal
)

func loadSecretMap(secretName string) (map[string]string, error) {
	secretJSON, err := getSecret(secretName)
	if err != nil {
		return nil, err
	}
	secrets := make(map[string]string)
	if err := json.Unmarshal([]byte(secretJSON), &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

func loadProdSecrets() error {
	jwtSecrets, err := loadSecretMap("prod/jwt")
	if err != nil {
		return fmt.Errorf("error retrieving JWT secret: %w", err)
	}
	for key, value := range jwtSecrets {
		os.Setenv(key, value)
	}

	pgSecrets, err := getSecret("prod/postgres")
	if err != nil {
		return fmt.Errorf("error retrieving Postgres secret: %w", err)
	}
	var pgValues map[string]interface{}
	if err := json.Unmarshal([]byte(pgSecrets), &pgValues); err != nil {
		return fmt.Errorf("error parsing Postgres secret JSON: %w", err)
	}
	os.Setenv("DB_USERNAME", pgValues["username"].(string))
	os.Setenv("DB_PASSWORD", pgValues["password"].(string))
	os.Setenv("DB_ENGINE", pgValues["engine"].(string))
	os.Setenv("DB_HOST", pgValues["host"].(string))
	os.Setenv("DB_PORT", fmt.Sprintf("%v", pgValues["port"]))
	os.Setenv("DB_INSTANCE_IDENTIFIER", pgValues["dbInstanceIdentifier"].(string))

	valkeySecrets, err := loadSecretMap("prod/valkey")
	if err == nil {
		for key, value := range valkeySecrets {
			os.Setenv(key, value)
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		logFatal(err)
	}
}

func run() error {
	if err := loadEnv(); err != nil {
		log.Println("No .env file found; using system environment variables")
	}
	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "dev"
	}
	log.Println("Environment:", appEnv)

	if appEnv == "prod" {
		if err := loadProdSecrets(); err != nil {
			return err
		}
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	if err := connectDB(cfg.DB); err != nil {
		return err
	}

	valkeyStore, err := newValkeyStore(cfg.Valkey)
	if err != nil {
		return fmt.Errorf("valkey connection error: %w", err)
	}
	defer valkeyStore.Close()

	authHandler := handlers.NewAuthHandler(cfg, valkeyStore)
	router := setupRoutes(cfg, authHandler)

	corsOpts := []gorillaHandlers.CORSOption{
		gorillaHandlers.AllowedOrigins(cfg.CORS.AllowedOrigins),
		gorillaHandlers.AllowedMethods([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}),
		gorillaHandlers.AllowedHeaders([]string{"Content-Type", "Authorization", "X-Requested-With"}),
		gorillaHandlers.AllowCredentials(),
	}

	corsHandler := gorillaHandlers.CORS(corsOpts...)(router)

	port := cfg.Port
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s in %s environment (CORS: %s)", port, cfg.AppEnv, strings.Join(cfg.CORS.AllowedOrigins, ","))
	return listenAndServe(":"+port, corsHandler)
}
