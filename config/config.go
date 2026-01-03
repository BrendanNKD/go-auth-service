package config

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv string
	Port   string
	DB     DatabaseConfig
	Auth   AuthConfig
	Cookie CookieConfig
	CORS   CORSConfig
	Valkey ValkeyConfig
}

type DatabaseConfig struct {
	Engine   string
	Host     string
	Port     string
	Name     string
	Username string
	Password string
	SSLMode  string
}

type AuthConfig struct {
	AccessTokenSecret  []byte
	RefreshTokenSecret []byte
	Issuer             string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	AccessCookieName   string
	RefreshCookieName  string
}

type CookieConfig struct {
	Domain   string
	Secure   bool
	SameSite http.SameSite
	Path     string
}

type CORSConfig struct {
	AllowedOrigins []string
}

type ValkeyConfig struct {
	Addr     string
	Password string
	DB       int
	Prefix   string
}

func Load() (Config, error) {
	appEnv := getEnv("APP_ENV", "dev")
	port := getEnv("APP_PORT", "8080")

	dbName := getEnv("DB_NAME", "")
	if dbName == "" {
		dbName = os.Getenv("DB_INSTANCE_IDENTIFIER")
	}

	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if accessSecret == "" || refreshSecret == "" {
		return Config{}, errors.New("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be set")
	}

	accessTTL, err := time.ParseDuration(getEnv("JWT_ACCESS_TTL", "15m"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid JWT_ACCESS_TTL: %w", err)
	}
	refreshTTL, err := time.ParseDuration(getEnv("JWT_REFRESH_TTL", "720h"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid JWT_REFRESH_TTL: %w", err)
	}

	cookieSecure := getEnvBool("COOKIE_SECURE", appEnv == "prod")
	sameSite, err := parseSameSite(getEnv("COOKIE_SAMESITE", "lax"))
	if err != nil {
		return Config{}, err
	}

	corsOrigins := parseCSV(getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"))

	valkeyDB, err := strconv.Atoi(getEnv("VALKEY_DB", "0"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid VALKEY_DB: %w", err)
	}

	dbSSLMode := getEnv("DB_SSLMODE", "")
	if dbSSLMode == "" {
		if appEnv == "prod" {
			dbSSLMode = "require"
		} else {
			dbSSLMode = "disable"
		}
	}

	cfg := Config{
		AppEnv: appEnv,
		Port:   port,
		DB: DatabaseConfig{
			Engine:   getEnv("DB_ENGINE", "postgres"),
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			Name:     dbName,
			Username: getEnv("DB_USERNAME", ""),
			Password: getEnv("DB_PASSWORD", ""),
			SSLMode:  dbSSLMode,
		},
		Auth: AuthConfig{
			AccessTokenSecret:  []byte(accessSecret),
			RefreshTokenSecret: []byte(refreshSecret),
			Issuer:             getEnv("JWT_ISSUER", "auth-service"),
			AccessTokenTTL:     accessTTL,
			RefreshTokenTTL:    refreshTTL,
			AccessCookieName:   getEnv("AUTH_ACCESS_COOKIE_NAME", "access_token"),
			RefreshCookieName:  getEnv("AUTH_REFRESH_COOKIE_NAME", "refresh_token"),
		},
		Cookie: CookieConfig{
			Domain:   getEnv("COOKIE_DOMAIN", ""),
			Secure:   cookieSecure,
			SameSite: sameSite,
			Path:     getEnv("COOKIE_PATH", "/"),
		},
		CORS: CORSConfig{
			AllowedOrigins: corsOrigins,
		},
		Valkey: ValkeyConfig{
			Addr:     getEnv("VALKEY_ADDR", "localhost:6379"),
			Password: getEnv("VALKEY_PASSWORD", ""),
			DB:       valkeyDB,
			Prefix:   getEnv("VALKEY_PREFIX", "auth:refresh"),
		},
	}

	if cfg.DB.Name == "" || cfg.DB.Username == "" {
		return Config{}, errors.New("DB_NAME (or DB_INSTANCE_IDENTIFIER) and DB_USERNAME must be set")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseCSV(value string) []string {
	parts := strings.Split(value, ",")
	var results []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			results = append(results, trimmed)
		}
	}
	return results
}

func parseSameSite(value string) (http.SameSite, error) {
	switch strings.ToLower(value) {
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return http.SameSiteDefaultMode, fmt.Errorf("invalid COOKIE_SAMESITE: %s", value)
	}
}
