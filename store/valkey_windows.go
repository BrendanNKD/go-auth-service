//go:build windows

package store

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	appconfig "auth-service/config"
)

const (
	valkeyDialTimeout    = 5 * time.Second
	valkeyCommandTimeout = 10 * time.Second
)

type nativeValkeyClient struct {
	conn    net.Conn
	reader  *bufio.Reader
	timeout time.Duration
	mu      sync.Mutex
}

type respError string

func (e respError) Error() string {
	return string(e)
}

func createValkeyClient(cfg appconfig.ValkeyConfig) (valkeyClient, error) {
	addr := valkeyDialAddr(cfg.Addr)
	host := hostFromAddr(addr)

	ctx, cancel := context.WithTimeout(context.Background(), valkeyDialTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	var (
		conn net.Conn
		err  error
	)
	if cfg.UseTLS {
		tlsDialer := tls.Dialer{
			NetDialer: dialer,
			Config: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: host,
			},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("valkey connect failed: %w", err)
	}

	client := &nativeValkeyClient{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		timeout: valkeyCommandTimeout,
	}

	if cfg.Password != "" {
		if err := client.auth(ctx, cfg.Password); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("valkey auth failed: %w", err)
		}
	}

	if cfg.DB != 0 {
		if _, err := client.do(ctx, "SELECT", strconv.Itoa(cfg.DB)); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("valkey select db failed: %w", err)
		}
	}

	return client, nil
}

func (c *nativeValkeyClient) auth(ctx context.Context, password string) error {
	_, err := c.do(ctx, "AUTH", "default", password)
	if err == nil {
		return nil
	}
	if !isAuthArityError(err) {
		return err
	}
	_, err = c.do(ctx, "AUTH", password)
	return err
}

func (c *nativeValkeyClient) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	args := []string{"SET", key, value}
	if ttl > 0 {
		if ttl%time.Second == 0 {
			args = append(args, "EX", strconv.FormatInt(int64(ttl/time.Second), 10))
		} else {
			args = append(args, "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
		}
	}
	_, err := c.do(ctx, args...)
	return err
}

func (c *nativeValkeyClient) Get(ctx context.Context, key string) (string, bool, error) {
	value, err := c.do(ctx, "GET", key)
	if err != nil {
		return "", false, err
	}
	if value == nil {
		return "", false, nil
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", false, fmt.Errorf("unexpected valkey GET response %T", value)
	}
	return stringValue, true, nil
}

func (c *nativeValkeyClient) Del(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	args := append([]string{"DEL"}, keys...)
	_, err := c.do(ctx, args...)
	return err
}

func (c *nativeValkeyClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *nativeValkeyClient) do(ctx context.Context, args ...string) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("valkey command requires at least one argument")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil, errors.New("valkey client is closed")
	}

	if err := c.conn.SetDeadline(commandDeadline(ctx, c.timeout)); err != nil {
		return nil, err
	}
	if err := writeRESPArray(c.conn, args); err != nil {
		return nil, err
	}
	return readRESPValue(c.reader)
}

func commandDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func valkeyDialAddr(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if !strings.Contains(addr, ":") {
		return net.JoinHostPort(addr, "6379")
	}
	return addr
}

func isAuthArityError(err error) bool {
	var redisErr respError
	if !errors.As(err, &redisErr) {
		return false
	}
	message := strings.ToLower(string(redisErr))
	return strings.Contains(message, "wrong number") || strings.Contains(message, "syntax")
}

func writeRESPArray(w io.Writer, args []string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(arg), arg); err != nil {
			return err
		}
	}
	return nil
}

func readRESPValue(r *bufio.Reader) (any, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	switch prefix {
	case '+':
		return readRESPLine(r)
	case '-':
		line, err := readRESPLine(r)
		if err != nil {
			return nil, err
		}
		return nil, respError(line)
	case ':':
		line, err := readRESPLine(r)
		if err != nil {
			return nil, err
		}
		return strconv.ParseInt(line, 10, 64)
	case '$':
		line, err := readRESPLine(r)
		if err != nil {
			return nil, err
		}
		length, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if length == -1 {
			return nil, nil
		}
		buf := make([]byte, length+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		if buf[length] != '\r' || buf[length+1] != '\n' {
			return nil, errors.New("invalid valkey bulk string terminator")
		}
		return string(buf[:length]), nil
	case '*':
		line, err := readRESPLine(r)
		if err != nil {
			return nil, err
		}
		length, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if length == -1 {
			return nil, nil
		}
		values := make([]any, length)
		for i := range values {
			values[i], err = readRESPValue(r)
			if err != nil {
				return nil, err
			}
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unexpected valkey response prefix %q", prefix)
	}
}

func readRESPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}
