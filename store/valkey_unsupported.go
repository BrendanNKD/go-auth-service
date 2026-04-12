//go:build !windows && !cgo

package store

import (
	"fmt"

	appconfig "auth-service/config"
)

func createValkeyClient(cfg appconfig.ValkeyConfig) (valkeyClient, error) {
	return nil, fmt.Errorf("valkey GLIDE requires CGO_ENABLED=1 on this platform")
}
