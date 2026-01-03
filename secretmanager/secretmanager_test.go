package secretmanager

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
)

type stubSecretsClient struct {
	output *secretsmanager.GetSecretValueOutput
	err    error
}

func (s stubSecretsClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.output, nil
}

func TestGetSecretLoadConfigError(t *testing.T) {
	originalLoad := loadDefaultConfig
	loadDefaultConfig = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, errors.New("config error")
	}
	defer func() { loadDefaultConfig = originalLoad }()

	_, err := GetSecret("secret")
	assert.Error(t, err)
}

func TestGetSecretClientError(t *testing.T) {
	originalLoad := loadDefaultConfig
	originalNew := newSecretsManagerClient
	loadDefaultConfig = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, nil
	}
	newSecretsManagerClient = func(cfg aws.Config) secretsManagerAPI {
		return stubSecretsClient{err: errors.New("client error")}
	}
	defer func() {
		loadDefaultConfig = originalLoad
		newSecretsManagerClient = originalNew
	}()

	_, err := GetSecret("secret")
	assert.Error(t, err)
}

func TestGetSecretSuccess(t *testing.T) {
	originalLoad := loadDefaultConfig
	originalNew := newSecretsManagerClient
	loadDefaultConfig = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, nil
	}
	newSecretsManagerClient = func(cfg aws.Config) secretsManagerAPI {
		return stubSecretsClient{output: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("value")}}
	}
	defer func() {
		loadDefaultConfig = originalLoad
		newSecretsManagerClient = originalNew
	}()

	value, err := GetSecret("secret")
	assert.NoError(t, err)
	assert.Equal(t, "value", value)
}

func TestNewSecretsManagerClientDefault(t *testing.T) {
	client := newSecretsManagerClient(aws.Config{})
	assert.NotNil(t, client)
}
