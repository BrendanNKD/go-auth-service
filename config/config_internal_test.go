package config

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnvBoolFallback(t *testing.T) {
	t.Setenv("TEST_BOOL", "")
	assert.True(t, getEnvBool("TEST_BOOL", true))

	t.Setenv("TEST_BOOL", "not-bool")
	assert.False(t, getEnvBool("TEST_BOOL", false))
}

func TestParseSameSiteModes(t *testing.T) {
	mode, err := parseSameSite("lax")
	assert.NoError(t, err)
	assert.Equal(t, http.SameSiteLaxMode, mode)

	mode, err = parseSameSite("none")
	assert.NoError(t, err)
	assert.Equal(t, http.SameSiteNoneMode, mode)
}
