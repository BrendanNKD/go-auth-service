package secretmanager

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type secretsManagerAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

var (
	loadDefaultConfig       = config.LoadDefaultConfig
	newSecretsManagerClient = func(cfg aws.Config) secretsManagerAPI {
		return secretsmanager.NewFromConfig(cfg)
	}
)

// GetSecret retrieves a secret value from AWS Secrets Manager.
// secretName is the name or ARN of the secret.
// It returns the secret string (e.g. JSON) or an error.
func GetSecret(secretName string) (string, error) {
	// Create a context for the API call.
	ctx := context.Background()

	// Load the AWS configuration (region, credentials, etc.).
	cfg, err := loadDefaultConfig(ctx)
	if err != nil {
		log.Printf("unable to load AWS SDK config: %v", err)
		return "", err
	}

	// Create a Secrets Manager client.
	client := newSecretsManagerClient(cfg)

	// Prepare the request.
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	// Call Secrets Manager to retrieve the secret.
	result, err := client.GetSecretValue(ctx, input)
	if err != nil {
		return "", err
	}

	// Return the secret string.
	return aws.ToString(result.SecretString), nil
}
