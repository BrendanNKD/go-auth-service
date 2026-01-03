package db

import (
	"database/sql"
	"errors"
	"testing"

	"auth-service/config"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestConnectSuccess(t *testing.T) {
	mockDB, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	assert.NoError(t, err)
	defer mockDB.Close()

	mock.ExpectPing()

	originalOpenDB := openDB
	openDB = func(driverName, dataSourceName string) (*sql.DB, error) {
		return mockDB, nil
	}
	defer func() { openDB = originalOpenDB }()

	cfg := config.DatabaseConfig{
		Engine:   "postgres",
		Host:     "localhost",
		Port:     "5432",
		Username: "user",
		Password: "pass",
		Name:     "db",
		SSLMode:  "disable",
	}

	assert.NoError(t, Connect(cfg))
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConnectUnsupportedEngine(t *testing.T) {
	cfg := config.DatabaseConfig{Engine: "mysql"}
	assert.Error(t, Connect(cfg))
}

func TestConnectOpenError(t *testing.T) {
	originalOpenDB := openDB
	openDB = func(driverName, dataSourceName string) (*sql.DB, error) {
		return nil, errors.New("open error")
	}
	defer func() { openDB = originalOpenDB }()

	cfg := config.DatabaseConfig{Engine: "postgres"}
	assert.Error(t, Connect(cfg))
}

func TestConnectPingError(t *testing.T) {
	mockDB, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	assert.NoError(t, err)
	defer mockDB.Close()

	mock.ExpectPing().WillReturnError(errors.New("ping error"))

	originalOpenDB := openDB
	openDB = func(driverName, dataSourceName string) (*sql.DB, error) {
		return mockDB, nil
	}
	defer func() { openDB = originalOpenDB }()

	cfg := config.DatabaseConfig{Engine: "postgres"}
	assert.Error(t, Connect(cfg))
	assert.NoError(t, mock.ExpectationsWereMet())
}
