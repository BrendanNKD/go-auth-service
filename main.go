package main

import (
	"auth-service/config"
	"auth-service/db"
	"auth-service/handlers"
	"auth-service/middleware"
	"auth-service/routes"
	"auth-service/secretmanager" // Ensure this is available in production.
	"auth-service/store"
	"auth-service/telemetry"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/joho/godotenv"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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
	setEnv         = func(key, value string) error {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set env %s: %w", key, err)
		}
		return nil
	}
)

const (
	defaultAppEnv  = "dev"
	defaultPort    = "8080"
	secretJWT      = "prod/jwt"
	secretPostgres = "prod/postgres"
	secretValkey   = "prod/valkey"
)

type postgresSecret struct {
	Username string      `json:"username"`
	Password string      `json:"password"`
	Engine   string      `json:"engine"`
	Host     string      `json:"host"`
	Port     json.Number `json:"port"`
	DBName   string      `json:"dbname"`
}

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

func setEnvFromMap(values map[string]string) error {
	for key, value := range values {
		if err := setEnv(key, value); err != nil {
			return err
		}
	}
	return nil
}

func loadPostgresSecret() (postgresSecret, error) {
	secretJSON, err := getSecret(secretPostgres)
	if err != nil {
		return postgresSecret{}, fmt.Errorf("error retrieving Postgres secret: %w", err)
	}
	var pgValues postgresSecret
	if err := json.Unmarshal([]byte(secretJSON), &pgValues); err != nil {
		return postgresSecret{}, fmt.Errorf("error parsing Postgres secret JSON: %w", err)
	}
	if err := validatePostgresSecret(pgValues); err != nil {
		return postgresSecret{}, err
	}
	return pgValues, nil
}

func validatePostgresSecret(secret postgresSecret) error {
	if secret.Username == "" || secret.Password == "" || secret.Engine == "" || secret.Host == "" {
		return fmt.Errorf("postgres secret missing required fields")
	}
	port, err := secret.Port.Int64()
	if err != nil || port <= 0 {
		return fmt.Errorf("postgres secret has invalid port: %s", secret.Port)
	}
	return nil
}

func loadProdSecrets() error {
	jwtSecrets, err := loadSecretMap(secretJWT)
	if err != nil {
		return fmt.Errorf("error retrieving JWT secret: %w", err)
	}
	if err := setEnvFromMap(jwtSecrets); err != nil {
		return err
	}

	pgValues, err := loadPostgresSecret()
	if err != nil {
		return err
	}
	if err := setEnv("DB_USERNAME", pgValues.Username); err != nil {
		return err
	}
	if err := setEnv("DB_PASSWORD", pgValues.Password); err != nil {
		return err
	}
	if err := setEnv("DB_ENGINE", pgValues.Engine); err != nil {
		return err
	}
	if err := setEnv("DB_HOST", pgValues.Host); err != nil {
		return err
	}
	if err := setEnv("DB_PORT", pgValues.Port.String()); err != nil {
		return err
	}
	if err := setEnv("DB_NAME", pgValues.DBName); err != nil {
		return err
	}

	valkeySecrets, err := loadSecretMap(secretValkey)
	if err == nil {
		if err := setEnvFromMap(valkeySecrets); err != nil {
			return err
		}
	} else {
		log.Printf("Valkey secrets not loaded: %v", err)
	}
	return nil
}

func resolveAppEnv() string {
	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		return defaultAppEnv
	}
	return appEnv
}

func buildCORSHandler(cfg config.Config, router http.Handler) http.Handler {
	corsOpts := []gorillaHandlers.CORSOption{
		gorillaHandlers.AllowedOrigins(cfg.CORS.AllowedOrigins),
		gorillaHandlers.AllowedMethods([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}),
		gorillaHandlers.AllowedHeaders([]string{"Content-Type", "Authorization", "X-Requested-With"}),
		gorillaHandlers.AllowCredentials(),
	}

	return gorillaHandlers.CORS(corsOpts...)(router)
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
	appEnv := resolveAppEnv()
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

	shutdownTelemetry, err := telemetry.Init(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("telemetry init error: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(shutdownCtx); err != nil {
			log.Printf("telemetry shutdown error: %v", err)
		}
	}()

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

	otelHandler := otelhttp.NewHandler(middleware.RequestLogger(router), "http.server")
	corsHandler := buildCORSHandler(cfg, otelHandler)

	port := cfg.Port
	if port == "" {
		port = defaultPort
	}

	log.Printf("Starting server on port %s in %s environment (CORS: %s)", port, cfg.AppEnv, strings.Join(cfg.CORS.AllowedOrigins, ","))
	return listenAndServe(":"+port, corsHandler)
}
