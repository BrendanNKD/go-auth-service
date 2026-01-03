package db

import (
	"database/sql"
	"fmt"
	"log"

	"auth-service/config"

	_ "github.com/lib/pq" // Postgres driver
)

var DB *sql.DB

func Connect(cfg config.DatabaseConfig) {
	if cfg.Engine != "postgres" {
		log.Fatalf("Unsupported database engine: %s", cfg.Engine)
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Name, cfg.SSLMode)

	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	log.Println("Successfully connected to the Postgres database")
}
