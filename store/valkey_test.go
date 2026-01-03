package store

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"auth-service/config"

	"github.com/stretchr/testify/assert"
)

func readCommand(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\r\n")
	if line == "" || line[0] != '*' {
		return nil, fmt.Errorf("invalid command")
	}
	var count int
	_, err = fmt.Sscanf(line, "*%d", &count)
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		lenLine, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		lenLine = strings.TrimSuffix(lenLine, "\r\n")
		var argLen int
		_, err = fmt.Sscanf(lenLine, "$%d", &argLen)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, argLen+2)
		if _, err := reader.Read(buf); err != nil {
			return nil, err
		}
		args = append(args, strings.TrimSuffix(string(buf), "\r\n"))
	}
	return args, nil
}

func startValkeyServer(t *testing.T, handler func([]string) string) (string, func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				writer := bufio.NewWriter(c)
				for {
					args, err := readCommand(reader)
					if err != nil {
						return
					}
					resp := handler(args)
					if _, err := writer.WriteString(resp); err != nil {
						return
					}
					if err := writer.Flush(); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	cleanup := func() {
		listener.Close()
	}

	return listener.Addr().String(), cleanup
}

func TestValkeyStoreOperations(t *testing.T) {
	addr, cleanup := startValkeyServer(t, func(args []string) string {
		switch strings.ToUpper(args[0]) {
		case "AUTH", "SELECT", "PING", "SET", "DEL":
			return "+OK\r\n"
		case "EXISTS":
			return ":1\r\n"
		default:
			return "-ERR\r\n"
		}
	})
	defer cleanup()

	cfg := config.ValkeyConfig{Addr: addr, Password: "pw", DB: 1, Prefix: "prefix"}
	store, err := NewValkeyStore(cfg)
	assert.NoError(t, err)

	err = store.Save(context.Background(), "token", "user", time.Second)
	assert.NoError(t, err)

	exists, err := store.Exists(context.Background(), "token")
	assert.NoError(t, err)
	assert.True(t, exists)

	err = store.Revoke(context.Background(), "token")
	assert.NoError(t, err)
	assert.Equal(t, "prefix:token", store.key("token"))
}

func TestNewValkeyStoreNoAuth(t *testing.T) {
	addr, cleanup := startValkeyServer(t, func(args []string) string {
		return "+PONG\r\n"
	})
	defer cleanup()

	cfg := config.ValkeyConfig{Addr: addr, Prefix: "prefix"}
	store, err := NewValkeyStore(cfg)
	assert.NoError(t, err)
	assert.NoError(t, store.Close())
}

func TestNewValkeyStorePingError(t *testing.T) {
	addr, cleanup := startValkeyServer(t, func(args []string) string {
		return "-ERR\r\n"
	})
	defer cleanup()

	cfg := config.ValkeyConfig{Addr: addr, Prefix: "prefix"}
	_, err := NewValkeyStore(cfg)
	assert.Error(t, err)
}

func TestValkeyStoreExistsInvalidResponse(t *testing.T) {
	addr, cleanup := startValkeyServer(t, func(args []string) string {
		if strings.ToUpper(args[0]) == "EXISTS" {
			return ":notint\r\n"
		}
		return "+OK\r\n"
	})
	defer cleanup()

	store := &ValkeyStore{addr: addr, prefix: "prefix"}
	_, err := store.Exists(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreExistsUnexpectedResponse(t *testing.T) {
	originalDial := dialContext
	dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return &stubConn{readData: []byte(":notint\r\n")}, nil
	}
	defer func() { dialContext = originalDial }()

	store := &ValkeyStore{addr: "ignored"}
	_, err := store.Exists(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreExistsDoError(t *testing.T) {
	store := &ValkeyStore{addr: "127.0.0.1:1"}
	_, err := store.Exists(context.Background(), "token")
	assert.Error(t, err)
}

func TestValkeyStoreDoError(t *testing.T) {
	store := &ValkeyStore{addr: "127.0.0.1:1"}
	_, err := store.do(context.Background(), "PING")
	assert.Error(t, err)
}

func TestValkeyStoreDoAuthError(t *testing.T) {
	addr, cleanup := startValkeyServer(t, func(args []string) string {
		if strings.ToUpper(args[0]) == "AUTH" {
			return "-ERR\r\n"
		}
		return "+OK\r\n"
	})
	defer cleanup()

	store := &ValkeyStore{addr: addr, password: "pw"}
	_, err := store.do(context.Background(), "PING")
	assert.Error(t, err)
}

func TestValkeyStoreDoSelectError(t *testing.T) {
	addr, cleanup := startValkeyServer(t, func(args []string) string {
		if strings.ToUpper(args[0]) == "SELECT" {
			return "-ERR\r\n"
		}
		return "+OK\r\n"
	})
	defer cleanup()

	store := &ValkeyStore{addr: addr, db: 1}
	_, err := store.do(context.Background(), "PING")
	assert.Error(t, err)
}

func TestValkeyStoreDoWriteErrors(t *testing.T) {
	originalDial := dialContext
	originalWriter := newBufioWriter
	newBufioWriter = func(w io.Writer) *bufio.Writer {
		return bufio.NewWriterSize(w, 1)
	}
	defer func() {
		dialContext = originalDial
		newBufioWriter = originalWriter
	}()

	dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return &stubConn{writeErr: fmt.Errorf("write error")}, nil
	}
	store := &ValkeyStore{addr: "ignored", password: "pw"}
	_, err := store.do(context.Background(), "PING")
	assert.Error(t, err)

	store = &ValkeyStore{addr: "ignored", db: 1}
	_, err = store.do(context.Background(), "PING")
	assert.Error(t, err)

	store = &ValkeyStore{addr: "ignored"}
	_, err = store.do(context.Background(), "PING")
	assert.Error(t, err)
}

func TestValkeyStoreDoReadErrors(t *testing.T) {
	originalDial := dialContext
	dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return &stubConn{readErr: fmt.Errorf("read error")}, nil
	}
	defer func() { dialContext = originalDial }()

	store := &ValkeyStore{addr: "ignored", password: "pw"}
	_, err := store.do(context.Background(), "PING")
	assert.Error(t, err)

	store = &ValkeyStore{addr: "ignored", db: 1}
	_, err = store.do(context.Background(), "PING")
	assert.Error(t, err)

	store = &ValkeyStore{addr: "ignored"}
	_, err = store.do(context.Background(), "PING")
	assert.Error(t, err)
}

func TestWriteCommandAndReadResponse(t *testing.T) {
	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	err := writeCommand(writer, "PING")
	assert.NoError(t, err)
	assert.NoError(t, writer.Flush())
	assert.Contains(t, builder.String(), "PING")

	reader := bufio.NewReader(strings.NewReader("+OK\r\n"))
	resp, err := readResponse(reader)
	assert.NoError(t, err)
	assert.Equal(t, "OK", resp)

	reader = bufio.NewReader(strings.NewReader(":1\r\n"))
	resp, err = readResponse(reader)
	assert.NoError(t, err)
	assert.Equal(t, "1", resp)

	reader = bufio.NewReader(strings.NewReader("$3\r\nfoo\r\n"))
	resp, err = readResponse(reader)
	assert.NoError(t, err)
	assert.Equal(t, "foo", resp)

	reader = bufio.NewReader(strings.NewReader("$-1\r\n"))
	resp, err = readResponse(reader)
	assert.NoError(t, err)
	assert.Equal(t, "", resp)

	reader = bufio.NewReader(strings.NewReader("-ERR\r\n"))
	_, err = readResponse(reader)
	assert.Error(t, err)

	reader = bufio.NewReader(strings.NewReader("\r\n"))
	_, err = readResponse(reader)
	assert.Error(t, err)

	reader = bufio.NewReader(strings.NewReader("?\r\n"))
	_, err = readResponse(reader)
	assert.Error(t, err)

	reader = bufio.NewReader(strings.NewReader("$x\r\n"))
	_, err = readResponse(reader)
	assert.Error(t, err)

	reader = bufio.NewReader(strings.NewReader(""))
	_, err = readResponse(reader)
	assert.Error(t, err)
}

func TestWriteCommandError(t *testing.T) {
	writer := bufio.NewWriterSize(errWriter{}, 1)
	err := writeCommand(writer, "PING")
	assert.Error(t, err)
}

func TestWriteCommandLoopError(t *testing.T) {
	writer := bufio.NewWriterSize(dollarFailWriter{}, 1)
	err := writeCommand(writer, "PING", "ARG")
	assert.Error(t, err)
}

func TestReadResponseBulkReadError(t *testing.T) {
	reader := bufio.NewReader(&errorReader{})
	_, err := readResponse(reader)
	assert.Error(t, err)
}

type errorReader struct {
	read bool
}

func (r *errorReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		return copy(p, "$5\r\n"), nil
	}
	return 0, fmt.Errorf("read error")
}

type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

type failAfterWriter struct {
	writes    int
	failAfter int
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > w.failAfter {
		return 0, fmt.Errorf("write error")
	}
	return len(p), nil
}

type dollarFailWriter struct{}

func (dollarFailWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "$") {
		return 0, fmt.Errorf("write error")
	}
	return len(p), nil
}

type stubConn struct {
	readData []byte
	readErr  error
	writeErr error
}

func (c *stubConn) Read(p []byte) (int, error) {
	if len(c.readData) > 0 {
		n := copy(p, c.readData)
		c.readData = c.readData[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, io.EOF
}

func (c *stubConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *stubConn) Close() error { return nil }

func (c *stubConn) LocalAddr() net.Addr { return &net.TCPAddr{} }

func (c *stubConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (c *stubConn) SetDeadline(t time.Time) error { return nil }

func (c *stubConn) SetReadDeadline(t time.Time) error { return nil }

func (c *stubConn) SetWriteDeadline(t time.Time) error { return nil }
