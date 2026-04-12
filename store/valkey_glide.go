//go:build !windows && cgo

package store

import (
	"context"
	"fmt"
	"time"

	appconfig "auth-service/config"

	glide "github.com/valkey-io/valkey-glide/go/v2"
	"github.com/valkey-io/valkey-glide/go/v2/config"
	"github.com/valkey-io/valkey-glide/go/v2/options"
)

type glideValkeyClient struct {
	client *glide.Client
}

func createValkeyClient(cfg appconfig.ValkeyConfig) (valkeyClient, error) {
	glideConfig := config.NewClientConfiguration().
		WithAddress(&config.NodeAddress{Host: hostFromAddr(cfg.Addr), Port: portFromAddr(cfg.Addr)}).
		WithDatabaseId(cfg.DB)

	if cfg.Password != "" {
		glideConfig.WithCredentials(config.NewServerCredentialsWithDefaultUsername(cfg.Password))
	}

	if cfg.UseTLS {
		glideConfig.WithUseTLS(true)
	}

	client, err := glide.NewClient(glideConfig)
	if err != nil {
		return nil, fmt.Errorf("valkey glide connect failed: %w", err)
	}
	return &glideValkeyClient{client: client}, nil
}

func (g *glideValkeyClient) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	opts := *options.NewSetOptions().SetExpiry(options.NewExpiryIn(ttl))
	_, err := g.client.SetWithOptions(ctx, key, value, opts)
	return err
}

func (g *glideValkeyClient) Get(ctx context.Context, key string) (string, bool, error) {
	result, err := g.client.Get(ctx, key)
	if err != nil {
		return "", false, err
	}
	if result.IsNil() {
		return "", false, nil
	}
	return result.Value(), true, nil
}

func (g *glideValkeyClient) Del(ctx context.Context, keys []string) error {
	_, err := g.client.Del(ctx, keys)
	return err
}

func (g *glideValkeyClient) Close() error {
	g.client.Close()
	return nil
}
