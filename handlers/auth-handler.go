package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"auth-service/config"
	"auth-service/db"
	"auth-service/middleware"
	"auth-service/models"
	"auth-service/store"
	"auth-service/utils"

	"golang.org/x/crypto/bcrypt"
)

var (
	generateFromPassword   = bcrypt.GenerateFromPassword
	compareHashAndPassword = bcrypt.CompareHashAndPassword
	randRead               = rand.Read
	generateToken          = utils.GenerateToken
)

type JSONResponse map[string]interface{}

type AuthHandler struct {
	cfg        config.Config
	tokenStore store.RefreshTokenStore
}

const defaultRoleName = "user"

func NewAuthHandler(cfg config.Config, tokenStore store.RefreshTokenStore) *AuthHandler {
	return &AuthHandler{cfg: cfg, tokenStore: tokenStore}
}

func (h *AuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return middleware.NewAppError(http.StatusBadRequest, "Invalid request payload", err)
	}

	if user.Username == "" || user.Password == "" {
		return middleware.NewAppError(http.StatusBadRequest, "Username and password are required", nil)
	}

	roleName := strings.TrimSpace(user.Role)
	if roleName == "" {
		roleName = defaultRoleName
	}

	hashedPassword, err := generateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return middleware.NewAppError(http.StatusInternalServerError, "Internal server error", err)
	}

	tx, err := db.DB.Begin()
	if err != nil {
		log.Printf("Error creating transaction: %v", err)
		return middleware.NewAppError(http.StatusInternalServerError, "Internal server error", err)
	}

	var roleID string
	if err := tx.QueryRow("SELECT id FROM roles WHERE name = $1", roleName).Scan(&roleID); err != nil {
		_ = tx.Rollback()
		if err == sql.ErrNoRows {
			return middleware.NewAppError(http.StatusBadRequest, "Invalid role", err)
		}
		log.Printf("Error loading role: %v", err)
		return middleware.NewAppError(http.StatusInternalServerError, "Internal server error", err)
	}

	email := sql.NullString{String: user.Email, Valid: user.Email != ""}

	_, err = tx.Exec("INSERT INTO users (username, email, password_hash, role_id) VALUES ($1, $2, $3, $4)",
		user.Username, email, string(hashedPassword), roleID)
	if err != nil {
		_ = tx.Rollback()
		log.Printf("Error inserting user into database: %v", err)
		return middleware.NewAppError(http.StatusConflict, "User already exists or database error", err)
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		return middleware.NewAppError(http.StatusInternalServerError, "Internal server error", err)
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(JSONResponse{"message": "User registered successfully"})
	return nil
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return middleware.NewAppError(http.StatusBadRequest, "Invalid request payload", err)
	}

	if user.Username == "" || user.Password == "" {
		return middleware.NewAppError(http.StatusBadRequest, "Username and password are required", nil)
	}

	var storedPassword, role string
	err := db.DB.QueryRow("SELECT u.password_hash, r.name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = $1", user.Username).Scan(&storedPassword, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			return middleware.NewAppError(http.StatusUnauthorized, "Invalid username or password", err)
		} else {
			log.Printf("Database error: %v", err)
			return middleware.NewAppError(http.StatusInternalServerError, "Internal server error", err)
		}
	}

	if err := compareHashAndPassword([]byte(storedPassword), []byte(user.Password)); err != nil {
		return middleware.NewAppError(http.StatusUnauthorized, "Invalid username or password", err)
	}

	accessToken, err := h.issueTokens(r.Context(), w, user.Username, role)
	if err != nil {
		log.Printf("Error issuing tokens: %v", err)
		return middleware.NewAppError(http.StatusInternalServerError, "Could not generate tokens", err)
	}

	json.NewEncoder(w).Encode(JSONResponse{
		"message":      "Login successful",
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(h.cfg.Auth.AccessTokenTTL.Seconds()),
	})
	return nil
}

func (h *AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	refreshToken, err := readCookie(r, h.cfg.Auth.RefreshCookieName)
	if err != nil {
		return middleware.NewAppError(http.StatusUnauthorized, "Refresh token is required", err)
	}

	claims, err := utils.ParseToken(refreshToken, h.cfg.Auth.RefreshTokenSecret)
	if err != nil {
		return middleware.NewAppError(http.StatusUnauthorized, "Invalid refresh token", err)
	}

	if err := h.validateRefreshToken(r.Context(), claims.ID); err != nil {
		return middleware.NewAppError(http.StatusUnauthorized, "Refresh token revoked", err)
	}

	accessToken, err := h.rotateTokens(r.Context(), w, claims)
	if err != nil {
		log.Printf("Error rotating tokens: %v", err)
		return middleware.NewAppError(http.StatusInternalServerError, "Could not refresh token", err)
	}

	json.NewEncoder(w).Encode(JSONResponse{
		"message":      "Token refreshed",
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(h.cfg.Auth.AccessTokenTTL.Seconds()),
	})
	return nil
}

func (h *AuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	refreshToken, err := readCookie(r, h.cfg.Auth.RefreshCookieName)
	if err == nil {
		if claims, parseErr := utils.ParseToken(refreshToken, h.cfg.Auth.RefreshTokenSecret); parseErr == nil {
			_ = h.tokenStore.Revoke(r.Context(), claims.ID)
		}
	}

	clearCookie(w, h.cfg, h.cfg.Auth.AccessCookieName)
	clearCookie(w, h.cfg, h.cfg.Auth.RefreshCookieName)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(JSONResponse{"message": "Logged out successfully"})
	return nil
}

func (h *AuthHandler) issueTokens(ctx context.Context, w http.ResponseWriter, username, role string) (string, error) {
	accessClaims := utils.Claims{
		Username: username,
		Role:     role,
	}

	accessToken, err := generateToken(accessClaims, h.cfg.Auth.AccessTokenTTL, h.cfg.Auth.Issuer, h.cfg.Auth.AccessTokenSecret)
	if err != nil {
		return "", err
	}

	refreshID, err := newTokenID()
	if err != nil {
		return "", err
	}
	refreshClaims := utils.Claims{
		Username: username,
		Role:     role,
	}
	refreshClaims.ID = refreshID

	refreshToken, err := generateToken(refreshClaims, h.cfg.Auth.RefreshTokenTTL, h.cfg.Auth.Issuer, h.cfg.Auth.RefreshTokenSecret)
	if err != nil {
		return "", err
	}

	if h.tokenStore == nil {
		return "", fmt.Errorf("token store not configured")
	}
	if err := h.tokenStore.Save(ctx, refreshID, username, h.cfg.Auth.RefreshTokenTTL); err != nil {
		return "", err
	}

	setCookie(w, h.cfg, h.cfg.Auth.AccessCookieName, accessToken, h.cfg.Auth.AccessTokenTTL)
	setCookie(w, h.cfg, h.cfg.Auth.RefreshCookieName, refreshToken, h.cfg.Auth.RefreshTokenTTL)
	return accessToken, nil
}

func (h *AuthHandler) validateRefreshToken(ctx context.Context, tokenID string) error {
	if h.tokenStore == nil {
		return fmt.Errorf("token store not configured")
	}
	if tokenID == "" {
		return fmt.Errorf("missing refresh token id")
	}

	exists, err := h.tokenStore.Exists(ctx, tokenID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("refresh token not found")
	}
	return nil
}

func (h *AuthHandler) rotateTokens(ctx context.Context, w http.ResponseWriter, claims *utils.Claims) (string, error) {
	if err := h.tokenStore.Revoke(ctx, claims.ID); err != nil {
		return "", err
	}
	return h.issueTokens(ctx, w, claims.Username, claims.Role)
}

func newTokenID() (string, error) {
	buffer := make([]byte, 32)
	if _, err := randRead(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func setCookie(w http.ResponseWriter, cfg config.Config, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cfg.Cookie.Path,
		Domain:   cfg.Cookie.Domain,
		HttpOnly: true,
		Secure:   cfg.Cookie.Secure,
		SameSite: cfg.Cookie.SameSite,
		MaxAge:   int(ttl.Seconds()),
	})
}

func clearCookie(w http.ResponseWriter, cfg config.Config, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     cfg.Cookie.Path,
		Domain:   cfg.Cookie.Domain,
		HttpOnly: true,
		Secure:   cfg.Cookie.Secure,
		SameSite: cfg.Cookie.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func readCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}
