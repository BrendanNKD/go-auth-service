package db

import (
	"database/sql"
	"fmt"
	"log"

	"auth-service/config"

	_ "github.com/lib/pq" // Postgres driver
)

var (
	DB     *sql.DB
	openDB = sql.Open
)

func Connect(cfg config.DatabaseConfig) error {
	if cfg.Engine != "postgres" {
		return fmt.Errorf("unsupported database engine: %s", cfg.Engine)
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Name, cfg.SSLMode)

	var err error
	DB, err = openDB("postgres", connStr)
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}

	if err = DB.Ping(); err != nil {
		return fmt.Errorf("error connecting to the database: %w", err)
	}

	log.Println("Successfully connected to the Postgres database")
	return nil
}
