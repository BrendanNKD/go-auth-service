package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"auth-service/config"
)

type RefreshTokenStore interface {
	SaveToken(ctx context.Context, tokenHash string, metadata RefreshTokenMetadata, ttl time.Duration) error
	GetToken(ctx context.Context, tokenHash string) (RefreshTokenMetadata, bool, error)
	RevokeToken(ctx context.Context, tokenHash string) error
	SaveSession(ctx context.Context, sessionID string, session RefreshSession, ttl time.Duration) error
	GetSession(ctx context.Context, sessionID string) (RefreshSession, bool, error)
	RevokeSession(ctx context.Context, sessionID string) error
	MarkRevoked(ctx context.Context, tokenHash, sessionID string, ttl time.Duration) error
	IsRevoked(ctx context.Context, tokenHash string) (string, bool, error)
	Close() error
}

var (
	dialContext    = (&net.Dialer{}).DialContext
	newBufioReader = bufio.NewReader
	newBufioWriter = bufio.NewWriter
	jsonMarshal    = json.Marshal
	jsonUnmarshal  = json.Unmarshal
)

type ValkeyStore struct {
	addr     string
	password string
	db       int
	prefix   string
	timeout  time.Duration
}

type RefreshTokenMetadata struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
}

type RefreshSession struct {
	CurrentTokenHash string    `json:"current_token_hash"`
	Username         string    `json:"username"`
	Role             string    `json:"role"`
	IssuedAt         time.Time `json:"issued_at"`
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

func (v *ValkeyStore) SaveToken(ctx context.Context, tokenHash string, metadata RefreshTokenMetadata, ttl time.Duration) error {
	seconds := strconv.FormatInt(int64(ttl.Seconds()), 10)
	payload, err := jsonMarshal(metadata)
	if err != nil {
		return err
	}
	_, err = v.do(ctx, "SET", v.tokenKey(tokenHash), string(payload), "EX", seconds)
	return err
}

func (v *ValkeyStore) GetToken(ctx context.Context, tokenHash string) (RefreshTokenMetadata, bool, error) {
	response, err := v.do(ctx, "GET", v.tokenKey(tokenHash))
	if err != nil {
		return RefreshTokenMetadata{}, false, err
	}
	if response == "" {
		return RefreshTokenMetadata{}, false, nil
	}
	var metadata RefreshTokenMetadata
	if err := jsonUnmarshal([]byte(response), &metadata); err != nil {
		return RefreshTokenMetadata{}, false, err
	}
	return metadata, true, nil
}

func (v *ValkeyStore) RevokeToken(ctx context.Context, tokenHash string) error {
	_, err := v.do(ctx, "DEL", v.tokenKey(tokenHash))
	return err
}

func (v *ValkeyStore) SaveSession(ctx context.Context, sessionID string, session RefreshSession, ttl time.Duration) error {
	seconds := strconv.FormatInt(int64(ttl.Seconds()), 10)
	payload, err := jsonMarshal(session)
	if err != nil {
		return err
	}
	_, err = v.do(ctx, "SET", v.sessionKey(sessionID), string(payload), "EX", seconds)
	return err
}

func (v *ValkeyStore) GetSession(ctx context.Context, sessionID string) (RefreshSession, bool, error) {
	response, err := v.do(ctx, "GET", v.sessionKey(sessionID))
	if err != nil {
		return RefreshSession{}, false, err
	}
	if response == "" {
		return RefreshSession{}, false, nil
	}
	var session RefreshSession
	if err := jsonUnmarshal([]byte(response), &session); err != nil {
		return RefreshSession{}, false, err
	}
	return session, true, nil
}

func (v *ValkeyStore) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := v.do(ctx, "DEL", v.sessionKey(sessionID))
	return err
}

func (v *ValkeyStore) MarkRevoked(ctx context.Context, tokenHash, sessionID string, ttl time.Duration) error {
	seconds := strconv.FormatInt(int64(ttl.Seconds()), 10)
	_, err := v.do(ctx, "SET", v.revokedKey(tokenHash), sessionID, "EX", seconds)
	return err
}

func (v *ValkeyStore) IsRevoked(ctx context.Context, tokenHash string) (string, bool, error) {
	response, err := v.do(ctx, "GET", v.revokedKey(tokenHash))
	if err != nil {
		return "", false, err
	}
	if response == "" {
		return "", false, nil
	}
	return response, true, nil
}

func (v *ValkeyStore) Close() error {
	return nil
}

func (v *ValkeyStore) tokenKey(tokenHash string) string {
	return fmt.Sprintf("%s:token:%s", v.prefix, tokenHash)
}

func (v *ValkeyStore) sessionKey(sessionID string) string {
	return fmt.Sprintf("%s:session:%s", v.prefix, sessionID)
}

func (v *ValkeyStore) revokedKey(tokenHash string) string {
	return fmt.Sprintf("%s:revoked:%s", v.prefix, tokenHash)
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
