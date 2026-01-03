package store

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"auth-service/config"
)

type RefreshTokenStore interface {
	Save(ctx context.Context, tokenID, username string, ttl time.Duration) error
	Exists(ctx context.Context, tokenID string) (bool, error)
	Revoke(ctx context.Context, tokenID string) error
	Close() error
}

var (
	dialContext    = (&net.Dialer{}).DialContext
	newBufioReader = bufio.NewReader
	newBufioWriter = bufio.NewWriter
)

type ValkeyStore struct {
	addr     string
	password string
	db       int
	prefix   string
	timeout  time.Duration
}

func NewValkeyStore(cfg config.ValkeyConfig) (*ValkeyStore, error) {
	store := &ValkeyStore{
		addr:     cfg.Addr,
		password: cfg.Password,
		db:       cfg.DB,
		prefix:   cfg.Prefix,
		timeout:  5 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := store.do(ctx, "PING"); err != nil {
		return nil, fmt.Errorf("valkey ping failed: %w", err)
	}

	return store, nil
}

func (v *ValkeyStore) Save(ctx context.Context, tokenID, username string, ttl time.Duration) error {
	seconds := strconv.FormatInt(int64(ttl.Seconds()), 10)
	_, err := v.do(ctx, "SET", v.key(tokenID), username, "EX", seconds)
	return err
}

func (v *ValkeyStore) Exists(ctx context.Context, tokenID string) (bool, error) {
	response, err := v.do(ctx, "EXISTS", v.key(tokenID))
	if err != nil {
		return false, err
	}

	count, err := strconv.Atoi(response)
	if err != nil {
		return false, fmt.Errorf("unexpected EXISTS response: %s", response)
	}
	return count > 0, nil
}

func (v *ValkeyStore) Revoke(ctx context.Context, tokenID string) error {
	_, err := v.do(ctx, "DEL", v.key(tokenID))
	return err
}

func (v *ValkeyStore) Close() error {
	return nil
}

func (v *ValkeyStore) key(tokenID string) string {
	return fmt.Sprintf("%s:%s", v.prefix, tokenID)
}

func (v *ValkeyStore) do(ctx context.Context, args ...string) (string, error) {
	conn, err := dialContext(ctx, "tcp", v.addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(v.timeout))
	}

	reader := newBufioReader(conn)
	writer := newBufioWriter(conn)

	if v.password != "" {
		if err := writeCommand(writer, "AUTH", v.password); err != nil {
			return "", err
		}
		if err := writer.Flush(); err != nil {
			return "", err
		}
		if _, err := readResponse(reader); err != nil {
			return "", err
		}
	}

	if v.db > 0 {
		if err := writeCommand(writer, "SELECT", strconv.Itoa(v.db)); err != nil {
			return "", err
		}
		if err := writer.Flush(); err != nil {
			return "", err
		}
		if _, err := readResponse(reader); err != nil {
			return "", err
		}
	}

	if err := writeCommand(writer, args...); err != nil {
		return "", err
	}
	if err := writer.Flush(); err != nil {
		return "", err
	}
	return readResponse(reader)
}

func writeCommand(writer *bufio.Writer, args ...string) error {
	if _, err := writer.WriteString(fmt.Sprintf("*%d\r\n", len(args))); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := writer.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg)); err != nil {
			return err
		}
	}
	return nil
}

func readResponse(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(line, "\r\n")
	if line == "" {
		return "", fmt.Errorf("empty response")
	}

	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return "", fmt.Errorf("valkey error: %s", line[1:])
	case ':':
		return line[1:], nil
	case '$':
		length, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", fmt.Errorf("invalid bulk length: %w", err)
		}
		if length == -1 {
			return "", nil
		}
		buffer := make([]byte, length+2)
		if _, err := reader.Read(buffer); err != nil {
			return "", err
		}
		return strings.TrimSuffix(string(buffer), "\r\n"), nil
	default:
		return "", fmt.Errorf("unexpected response: %s", line)
	}
}
