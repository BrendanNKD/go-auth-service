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

func loadSecretMap(secretName string) (map[string]string, error) {
	secretJSON, err := secretmanager.GetSecret(secretName)
	if err != nil {
		return nil, err
	}
	secrets := make(map[string]string)
	if err := json.Unmarshal([]byte(secretJSON), &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

func loadProdSecrets() {
	jwtSecrets, err := loadSecretMap("prod/jwt")
	if err != nil {
		log.Fatalf("Error retrieving JWT secret: %v", err)
	}
	for key, value := range jwtSecrets {
		os.Setenv(key, value)
	}

	pgSecrets, err := secretmanager.GetSecret("prod/postgres")
	if err != nil {
		log.Fatalf("Error retrieving Postgres secret: %v", err)
	}
	var pgValues map[string]interface{}
	if err := json.Unmarshal([]byte(pgSecrets), &pgValues); err != nil {
		log.Fatalf("Error parsing Postgres secret JSON: %v", err)
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
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found; using system environment variables")
	}

	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "dev"
	}
	log.Println("Environment:", appEnv)

	if appEnv == "prod" {
		loadProdSecrets()
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	db.Connect(cfg.DB)

	valkeyStore, err := store.NewValkeyStore(cfg.Valkey)
	if err != nil {
		log.Fatalf("Valkey connection error: %v", err)
	}
	defer valkeyStore.Close()

	authHandler := handlers.NewAuthHandler(cfg, valkeyStore)
	router := routes.SetupRoutes(cfg, authHandler)

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
	log.Fatal(http.ListenAndServe(":"+port, corsHandler))
}
