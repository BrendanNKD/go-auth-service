//go:build windows

package store

import (
	"bufio"
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteRESPArray(t *testing.T) {
	var buf bytes.Buffer

	err := writeRESPArray(&buf, []string{"SET", "key", "value"})

	require.NoError(t, err)
	assert.Equal(t, "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n", buf.String())
}

func TestReadRESPValue(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     any
	}{
		{name: "simple string", response: "+OK\r\n", want: "OK"},
		{name: "integer", response: ":2\r\n", want: int64(2)},
		{name: "bulk string", response: "$5\r\nvalue\r\n", want: "value"},
		{name: "nil bulk string", response: "$-1\r\n", want: nil},
		{name: "array", response: "*2\r\n$3\r\none\r\n$3\r\ntwo\r\n", want: []any{"one", "two"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readRESPValue(bufio.NewReader(bytes.NewBufferString(tt.response)))

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadRESPError(t *testing.T) {
	_, err := readRESPValue(bufio.NewReader(bytes.NewBufferString("-ERR bad command\r\n")))

	var redisErr respError
	require.True(t, errors.As(err, &redisErr))
	assert.Equal(t, respError("ERR bad command"), redisErr)
}
