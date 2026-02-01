package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv    string
	Port      string
	DB        DatabaseConfig
	Auth      AuthConfig
	Cookie    CookieConfig
	CORS      CORSConfig
	Valkey    ValkeyConfig
	Telemetry TelemetryConfig
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
	AccessTokenPrivateKey *rsa.PrivateKey
	AccessTokenPublicKey  *rsa.PublicKey
	AccessTokenKeyID      string
	Issuer                string
	AccessTokenTTL        time.Duration
	RefreshTokenTTL       time.Duration
	AccessCookieName      string
	RefreshCookieName     string
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

type TelemetryConfig struct {
	OTLPEndpoint         string
	OTLPTracesEndpoint   string
	OTLPMetricsEndpoint  string
	OTLPProtocol         string
	OTLPHeaders          map[string]string
	OTLPInsecure         bool
	ExportTimeout        time.Duration
	MetricExportInterval time.Duration
	ServiceName          string
	ServiceVersion       string
}

func Load() (Config, error) {
	appEnv := getEnv("APP_ENV", "dev")
	port := getEnv("APP_PORT", "8080")

	dbName := getEnv("DB_NAME", "")

	accessPrivateKeyPEM := normalizePEMEnv(os.Getenv("JWT_ACCESS_PRIVATE_KEY"))
	accessPublicKeyPEM := normalizePEMEnv(os.Getenv("JWT_ACCESS_PUBLIC_KEY"))
	if accessPrivateKeyPEM == "" {
		return Config{}, errors.New("JWT_ACCESS_PRIVATE_KEY must be set")
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

	telemetryHeaders, err := parseKeyValuePairs(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid OTEL_EXPORTER_OTLP_HEADERS: %w", err)
	}
	telemetryTimeout, err := getEnvDuration("OTEL_EXPORTER_OTLP_TIMEOUT", "10s")
	if err != nil {
		return Config{}, fmt.Errorf("invalid OTEL_EXPORTER_OTLP_TIMEOUT: %w", err)
	}
	metricInterval, err := getEnvDuration("OTEL_METRIC_EXPORT_INTERVAL", "15s")
	if err != nil {
		return Config{}, fmt.Errorf("invalid OTEL_METRIC_EXPORT_INTERVAL: %w", err)
	}

	dbSSLMode := getEnv("DB_SSLMODE", "")
	if dbSSLMode == "" {
		if appEnv == "prod" {
			dbSSLMode = "require"
		} else {
			dbSSLMode = "disable"
		}
	}

	privateKey, err := parseRSAPrivateKey(accessPrivateKeyPEM)
	if err != nil {
		return Config{}, err
	}
	publicKey := privateKey.Public().(*rsa.PublicKey)
	if accessPublicKeyPEM != "" {
		publicKey, err = parseRSAPublicKey(accessPublicKeyPEM)
		if err != nil {
			return Config{}, err
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
			AccessTokenPrivateKey: privateKey,
			AccessTokenPublicKey:  publicKey,
			AccessTokenKeyID:      getEnv("JWT_ACCESS_KID", "auth-service-1"),
			Issuer:                getEnv("JWT_ISSUER", "auth-service"),
			AccessTokenTTL:        accessTTL,
			RefreshTokenTTL:       refreshTTL,
			AccessCookieName:      getEnv("AUTH_ACCESS_COOKIE_NAME", "access_token"),
			RefreshCookieName:     getEnv("AUTH_REFRESH_COOKIE_NAME", "refresh_token"),
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
		Telemetry: TelemetryConfig{
			OTLPEndpoint:         getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			OTLPTracesEndpoint:   getEnv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", ""),
			OTLPMetricsEndpoint:  getEnv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", ""),
			OTLPProtocol:         strings.ToLower(getEnv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")),
			OTLPHeaders:          telemetryHeaders,
			OTLPInsecure:         getEnvBool("OTEL_EXPORTER_OTLP_INSECURE", false),
			ExportTimeout:        telemetryTimeout,
			MetricExportInterval: metricInterval,
			ServiceName:          getEnv("OTEL_SERVICE_NAME", "auth-service"),
			ServiceVersion:       getEnv("OTEL_SERVICE_VERSION", "dev"),
		},
	}

	if cfg.DB.Name == "" || cfg.DB.Username == "" {
		return Config{}, errors.New("DB_NAME and DB_USERNAME must be set")
	}

	return cfg, nil
}

func parseRSAPrivateKey(pemValue string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, errors.New("invalid JWT_ACCESS_PRIVATE_KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("JWT_ACCESS_PRIVATE_KEY is not RSA")
		}
		return privateKey, nil
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_ACCESS_PRIVATE_KEY: %w", err)
	}
	return privateKey, nil
}

func parseRSAPublicKey(pemValue string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, errors.New("invalid JWT_ACCESS_PUBLIC_KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_ACCESS_PUBLIC_KEY: %w", err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("JWT_ACCESS_PUBLIC_KEY is not RSA")
	}
	return publicKey, nil
}

func normalizePEMEnv(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
		(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
		value = value[1 : len(value)-1]
	}
	value = strings.ReplaceAll(value, `\r\n`, "\n")
	value = strings.ReplaceAll(value, `\n`, "\n")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return value
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

func getEnvDuration(key, fallback string) (time.Duration, error) {
	value := getEnv(key, fallback)
	parsed, err := time.ParseDuration(value)
	if err != nil {
		parsedInt, intErr := strconv.Atoi(value)
		if intErr != nil {
			return 0, err
		}
		return time.Duration(parsedInt) * time.Millisecond, nil
	}
	return parsed, nil
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

func parseKeyValuePairs(value string) (map[string]string, error) {
	headers := make(map[string]string)
	if strings.TrimSpace(value) == "" {
		return headers, nil
	}
	parts := strings.Split(value, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		keyValue := strings.SplitN(trimmed, "=", 2)
		if len(keyValue) != 2 {
			return nil, fmt.Errorf("invalid key-value pair: %s", trimmed)
		}
		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])
		if key == "" || value == "" {
			return nil, fmt.Errorf("invalid key-value pair: %s", trimmed)
		}
		headers[key] = value
	}
	return headers, nil
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
