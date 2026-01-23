package main

import (
	"errors"
	"testing"
)

func TestSetEnvError(t *testing.T) {
	err := setEnv("", "value")
	if err == nil {
		t.Fatalf("expected error for empty key")
	}
}

func TestSetEnvFromMapError(t *testing.T) {
	err := setEnvFromMap(map[string]string{"": "value"})
	if err == nil {
		t.Fatalf("expected error for invalid key")
	}
}

func TestValidatePostgresSecret(t *testing.T) {
	err := validatePostgresSecret(postgresSecret{})
	if err == nil {
		t.Fatalf("expected error for missing fields")
	}

	err = validatePostgresSecret(postgresSecret{
		Username:             "user",
		Password:             "pass",
		Engine:               "postgres",
		Host:                 "host",
		DBInstanceIdentifier: "db",
		Port:                 0,
	})
	if err == nil {
		t.Fatalf("expected error for invalid port")
	}

	err = validatePostgresSecret(postgresSecret{
		Username:             "user",
		Password:             "pass",
		Engine:               "postgres",
		Host:                 "host",
		DBInstanceIdentifier: "db",
		Port:                 5432,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestLoadPostgresSecretValidationError(t *testing.T) {
	originalGetSecret := getSecret
	getSecret = func(name string) (string, error) {
		return `{"username":"","password":"pass","engine":"postgres","host":"localhost","port":5432,"dbInstanceIdentifier":"db"}`, nil
	}
	defer func() { getSecret = originalGetSecret }()

	_, err := loadPostgresSecret()
	if err == nil {
		t.Fatalf("expected error for invalid secret")
	}
}

func TestLoadProdSecretsValkeyOptional(t *testing.T) {
	originalGetSecret := getSecret
	getSecret = func(name string) (string, error) {
		switch name {
		case "prod/jwt":
			return `{"JWT_ACCESS_PRIVATE_KEY":"private","JWT_ACCESS_PUBLIC_KEY":"public","JWT_ACCESS_KID":"kid"}`, nil
		case "prod/postgres":
			return `{"username":"user","password":"pass","engine":"postgres","host":"localhost","port":5432,"dbInstanceIdentifier":"db"}`, nil
		case "prod/valkey":
			return "", errors.New("missing")
		default:
			return "", errors.New("unknown")
		}
	}
	defer func() { getSecret = originalGetSecret }()

	if err := loadProdSecrets(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestLoadProdSecretsSetEnvFailures(t *testing.T) {
	originalGetSecret := getSecret
	originalSetEnv := setEnv
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
	defer func() {
		getSecret = originalGetSecret
		setEnv = originalSetEnv
	}()

	failKeys := []string{
		"JWT_ACCESS_PRIVATE_KEY",
		"DB_USERNAME",
		"DB_PASSWORD",
		"DB_ENGINE",
		"DB_HOST",
		"DB_PORT",
		"DB_INSTANCE_IDENTIFIER",
		"VALKEY_ADDR",
	}

	for _, failKey := range failKeys {
		t.Run(failKey, func(t *testing.T) {
			setEnv = func(key, value string) error {
				if key == failKey {
					return errors.New("setenv error")
				}
				return nil
			}

			err := loadProdSecrets()
			if err == nil {
				t.Fatalf("expected error for key %s", failKey)
			}
		})
	}
}
