package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"os"
	"testing"

	"auth-service/config"
	"auth-service/handlers"
	"auth-service/store"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestLoadSecretMapErrors(t *testing.T) {
	originalGetSecret := getSecret
	getSecret = func(name string) (string, error) {
		return "", errors.New("secret error")
	}
	defer func() { getSecret = originalGetSecret }()

	_, err := loadSecretMap("prod/jwt")
	assert.Error(t, err)

	getSecret = func(name string) (string, error) {
		return "not-json", nil
	}
	_, err = loadSecretMap("prod/jwt")
	assert.Error(t, err)
}

func TestLoadProdSecretsSuccess(t *testing.T) {
	originalGetSecret := getSecret
	getSecret = func(name string) (string, error) {
		switch name {
		case "prod/jwt":
			return `{"JWT_ACCESS_PRIVATE_KEY":"private","JWT_ACCESS_PUBLIC_KEY":"public","JWT_ACCESS_KID":"kid"}`, nil
		case "prod/postgres":
			return `{"username":"user","password":"pass","engine":"postgres","host":"localhost","port":5432,"dbInstanceIdentifier":"db"}`, nil
		case "prod/valkey":
			return `{"VALKEY_ADDR":"localhost:6379"}`, nil
		default:
			return "", errors.New("unknown")
		}
	}
	defer func() { getSecret = originalGetSecret }()

	assert.NoError(t, loadProdSecrets())
	assert.Equal(t, "private", os.Getenv("JWT_ACCESS_PRIVATE_KEY"))
	assert.Equal(t, "public", os.Getenv("JWT_ACCESS_PUBLIC_KEY"))
	assert.Equal(t, "user", os.Getenv("DB_USERNAME"))
	assert.Equal(t, "localhost", os.Getenv("DB_HOST"))
	assert.Equal(t, "localhost:6379", os.Getenv("VALKEY_ADDR"))
}

func TestLoadProdSecretsInvalidPostgresJSON(t *testing.T) {
	originalGetSecret := getSecret
	getSecret = func(name string) (string, error) {
		switch name {
		case "prod/jwt":
			return `{"JWT_ACCESS_PRIVATE_KEY":"private","JWT_ACCESS_PUBLIC_KEY":"public","JWT_ACCESS_KID":"kid"}`, nil
		case "prod/postgres":
			return "not-json", nil
		default:
			return "", errors.New("unknown")
		}
	}
	defer func() { getSecret = originalGetSecret }()

	assert.Error(t, loadProdSecrets())
}

func TestLoadProdSecretsPostgresError(t *testing.T) {
	originalGetSecret := getSecret
	getSecret = func(name string) (string, error) {
		switch name {
		case "prod/jwt":
			return `{"JWT_ACCESS_PRIVATE_KEY":"private","JWT_ACCESS_PUBLIC_KEY":"public","JWT_ACCESS_KID":"kid"}`, nil
		case "prod/postgres":
			return "", errors.New("postgres error")
		default:
			return "", errors.New("unknown")
		}
	}
	defer func() { getSecret = originalGetSecret }()

	assert.Error(t, loadProdSecrets())
}

func TestLoadProdSecretsError(t *testing.T) {
	originalGetSecret := getSecret
	getSecret = func(name string) (string, error) {
		return "", errors.New("secret error")
	}
	defer func() { getSecret = originalGetSecret }()

	assert.Error(t, loadProdSecrets())
}

func TestRunSuccess(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	originalLoadEnv := loadEnv
	originalLoadConfig := loadConfig
	originalConnectDB := connectDB
	originalNewValkeyStore := newValkeyStore
	originalSetupRoutes := setupRoutes
	originalListenAndServe := listenAndServe

	loadEnv = func(_ ...string) error { return errors.New("no env") }
	loadConfig = func() (config.Config, error) {
		privateKey := testPrivateKey(t)
		return config.Config{
			AppEnv: "dev",
			Auth: config.AuthConfig{
				AccessTokenPrivateKey: privateKey,
				AccessTokenPublicKey:  &privateKey.PublicKey,
				AccessTokenKeyID:      "kid",
				AccessCookieName:      "access",
				RefreshCookieName:     "refresh",
			},
			CORS: config.CORSConfig{AllowedOrigins: []string{"http://localhost"}},
		}, nil
	}
	connectDB = func(cfg config.DatabaseConfig) error { return nil }
	newValkeyStore = func(cfg config.ValkeyConfig) (*store.ValkeyStore, error) { return &store.ValkeyStore{}, nil }
	setupRoutes = func(cfg config.Config, authHandler *handlers.AuthHandler) *mux.Router {
		return mux.NewRouter()
	}
	listenAndServe = func(addr string, handler http.Handler) error { return nil }

	defer func() {
		loadEnv = originalLoadEnv
		loadConfig = originalLoadConfig
		connectDB = originalConnectDB
		newValkeyStore = originalNewValkeyStore
		setupRoutes = originalSetupRoutes
		listenAndServe = originalListenAndServe
	}()

	assert.NoError(t, run())
}

func TestRunDefaultEnv(t *testing.T) {
	t.Setenv("APP_ENV", "")
	originalLoadConfig := loadConfig
	originalConnectDB := connectDB
	originalNewValkeyStore := newValkeyStore
	originalSetupRoutes := setupRoutes
	originalListenAndServe := listenAndServe

	loadConfig = func() (config.Config, error) {
		privateKey := testPrivateKey(t)
		return config.Config{
			AppEnv: "dev",
			Auth: config.AuthConfig{
				AccessTokenPrivateKey: privateKey,
				AccessTokenPublicKey:  &privateKey.PublicKey,
				AccessTokenKeyID:      "kid",
				AccessCookieName:      "access",
				RefreshCookieName:     "refresh",
			},
			CORS: config.CORSConfig{AllowedOrigins: []string{"http://localhost"}},
		}, nil
	}
	connectDB = func(cfg config.DatabaseConfig) error { return nil }
	newValkeyStore = func(cfg config.ValkeyConfig) (*store.ValkeyStore, error) { return &store.ValkeyStore{}, nil }
	setupRoutes = func(cfg config.Config, authHandler *handlers.AuthHandler) *mux.Router {
		return mux.NewRouter()
	}
	listenAndServe = func(addr string, handler http.Handler) error { return nil }

	defer func() {
		loadConfig = originalLoadConfig
		connectDB = originalConnectDB
		newValkeyStore = originalNewValkeyStore
		setupRoutes = originalSetupRoutes
		listenAndServe = originalListenAndServe
	}()

	assert.NoError(t, run())
}

func TestRunProdSecretsError(t *testing.T) {
	t.Setenv("APP_ENV", "prod")
	originalGetSecret := getSecret
	originalLoadConfig := loadConfig
	getSecret = func(name string) (string, error) { return "", errors.New("secret error") }
	loadConfig = func() (config.Config, error) {
		return config.Config{}, nil
	}
	defer func() {
		getSecret = originalGetSecret
		loadConfig = originalLoadConfig
	}()

	assert.Error(t, run())
}

func TestRunConfigError(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	originalLoadConfig := loadConfig
	loadConfig = func() (config.Config, error) { return config.Config{}, errors.New("config error") }
	defer func() { loadConfig = originalLoadConfig }()

	assert.Error(t, run())
}

func TestRunConnectDBError(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	originalLoadConfig := loadConfig
	originalConnectDB := connectDB
	loadConfig = func() (config.Config, error) {
		privateKey := testPrivateKey(t)
		return config.Config{Auth: config.AuthConfig{AccessTokenPrivateKey: privateKey, AccessTokenPublicKey: &privateKey.PublicKey}}, nil
	}
	connectDB = func(cfg config.DatabaseConfig) error { return errors.New("db error") }
	defer func() {
		loadConfig = originalLoadConfig
		connectDB = originalConnectDB
	}()

	assert.Error(t, run())
}

func TestRunValkeyError(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	originalLoadConfig := loadConfig
	originalConnectDB := connectDB
	originalNewValkeyStore := newValkeyStore
	loadConfig = func() (config.Config, error) {
		privateKey := testPrivateKey(t)
		return config.Config{Auth: config.AuthConfig{AccessTokenPrivateKey: privateKey, AccessTokenPublicKey: &privateKey.PublicKey}}, nil
	}
	connectDB = func(cfg config.DatabaseConfig) error { return nil }
	newValkeyStore = func(cfg config.ValkeyConfig) (*store.ValkeyStore, error) { return nil, errors.New("valkey error") }
	defer func() {
		loadConfig = originalLoadConfig
		connectDB = originalConnectDB
		newValkeyStore = originalNewValkeyStore
	}()

	assert.Error(t, run())
}

func TestRunListenError(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	originalLoadConfig := loadConfig
	originalConnectDB := connectDB
	originalNewValkeyStore := newValkeyStore
	originalSetupRoutes := setupRoutes
	originalListenAndServe := listenAndServe

	loadConfig = func() (config.Config, error) {
		privateKey := testPrivateKey(t)
		return config.Config{
			AppEnv: "dev",
			Auth: config.AuthConfig{
				AccessTokenPrivateKey: privateKey,
				AccessTokenPublicKey:  &privateKey.PublicKey,
				AccessTokenKeyID:      "kid",
				AccessCookieName:      "access",
				RefreshCookieName:     "refresh",
			},
			CORS: config.CORSConfig{AllowedOrigins: []string{"http://localhost"}},
		}, nil
	}
	connectDB = func(cfg config.DatabaseConfig) error { return nil }
	newValkeyStore = func(cfg config.ValkeyConfig) (*store.ValkeyStore, error) { return &store.ValkeyStore{}, nil }
	setupRoutes = func(cfg config.Config, authHandler *handlers.AuthHandler) *mux.Router {
		return mux.NewRouter()
	}
	listenAndServe = func(addr string, handler http.Handler) error { return errors.New("listen error") }

	defer func() {
		loadConfig = originalLoadConfig
		connectDB = originalConnectDB
		newValkeyStore = originalNewValkeyStore
		setupRoutes = originalSetupRoutes
		listenAndServe = originalListenAndServe
	}()

	assert.Error(t, run())
}

func TestMainFunction(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	originalLoadConfig := loadConfig
	originalConnectDB := connectDB
	originalNewValkeyStore := newValkeyStore
	originalSetupRoutes := setupRoutes
	originalListenAndServe := listenAndServe
	originalLogFatal := logFatal

	loadConfig = func() (config.Config, error) {
		privateKey := testPrivateKey(t)
		return config.Config{
			AppEnv: "dev",
			Auth: config.AuthConfig{
				AccessTokenPrivateKey: privateKey,
				AccessTokenPublicKey:  &privateKey.PublicKey,
				AccessTokenKeyID:      "kid",
				AccessCookieName:      "access",
				RefreshCookieName:     "refresh",
			},
			CORS: config.CORSConfig{AllowedOrigins: []string{"http://localhost"}},
		}, nil
	}
	connectDB = func(cfg config.DatabaseConfig) error { return nil }
	newValkeyStore = func(cfg config.ValkeyConfig) (*store.ValkeyStore, error) { return &store.ValkeyStore{}, nil }
	setupRoutes = func(cfg config.Config, authHandler *handlers.AuthHandler) *mux.Router {
		return mux.NewRouter()
	}
	listenAndServe = func(addr string, handler http.Handler) error { return nil }

	defer func() {
		loadConfig = originalLoadConfig
		connectDB = originalConnectDB
		newValkeyStore = originalNewValkeyStore
		setupRoutes = originalSetupRoutes
		listenAndServe = originalListenAndServe
		logFatal = originalLogFatal
	}()

	main()
}

func TestMainFunctionError(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	originalLoadConfig := loadConfig
	originalLogFatal := logFatal
	loadConfig = func() (config.Config, error) { return config.Config{}, errors.New("config error") }
	called := false
	logFatal = func(args ...interface{}) {
		called = true
	}
	defer func() {
		loadConfig = originalLoadConfig
		logFatal = originalLogFatal
	}()

	main()
	assert.True(t, called)
}

func testPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	return privateKey
}
