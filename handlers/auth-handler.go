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

func NewAuthHandler(cfg config.Config, tokenStore store.RefreshTokenStore) *AuthHandler {
	return &AuthHandler{cfg: cfg, tokenStore: tokenStore}
}

func (h *AuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user models.Users
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if user.Username == "" || user.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := generateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, err = db.DB.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)",
		user.Username, string(hashedPassword), user.Role)
	if err != nil {
		log.Printf("Error inserting user into database: %v", err)
		http.Error(w, "User already exists or database error", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(JSONResponse{"message": "User registered successfully"})
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user models.Users
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if user.Username == "" || user.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	var storedPassword, role string
	err := db.DB.QueryRow("SELECT password, role FROM users WHERE username = $1", user.Username).Scan(&storedPassword, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		} else {
			log.Printf("Database error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if err := compareHashAndPassword([]byte(storedPassword), []byte(user.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if err := h.issueTokens(r.Context(), w, user.Username, role); err != nil {
		log.Printf("Error issuing tokens: %v", err)
		http.Error(w, "Could not generate tokens", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(JSONResponse{"message": "Login successful"})
}

func (h *AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	refreshToken, err := readCookie(r, h.cfg.Auth.RefreshCookieName)
	if err != nil {
		http.Error(w, "Refresh token is required", http.StatusUnauthorized)
		return
	}

	claims, err := utils.ParseToken(refreshToken, h.cfg.Auth.RefreshTokenSecret)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	if err := h.validateRefreshToken(r.Context(), claims.ID); err != nil {
		http.Error(w, "Refresh token revoked", http.StatusUnauthorized)
		return
	}

	if err := h.rotateTokens(r.Context(), w, claims); err != nil {
		log.Printf("Error rotating tokens: %v", err)
		http.Error(w, "Could not refresh token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(JSONResponse{"message": "Token refreshed"})
}

func (h *AuthHandler) AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":    true,
		"message":  "Token is valid",
		"username": claims.Username,
		"role":     claims.Role,
	})
}

func (h *AuthHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
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
}

func (h *AuthHandler) issueTokens(ctx context.Context, w http.ResponseWriter, username, role string) error {
	accessClaims := utils.Claims{
		Username: username,
		Role:     role,
	}

	accessToken, err := generateToken(accessClaims, h.cfg.Auth.AccessTokenTTL, h.cfg.Auth.Issuer, h.cfg.Auth.AccessTokenSecret)
	if err != nil {
		return err
	}

	refreshID, err := newTokenID()
	if err != nil {
		return err
	}
	refreshClaims := utils.Claims{
		Username: username,
		Role:     role,
	}
	refreshClaims.ID = refreshID

	refreshToken, err := generateToken(refreshClaims, h.cfg.Auth.RefreshTokenTTL, h.cfg.Auth.Issuer, h.cfg.Auth.RefreshTokenSecret)
	if err != nil {
		return err
	}

	if h.tokenStore == nil {
		return fmt.Errorf("token store not configured")
	}
	if err := h.tokenStore.Save(ctx, refreshID, username, h.cfg.Auth.RefreshTokenTTL); err != nil {
		return err
	}

	setCookie(w, h.cfg, h.cfg.Auth.AccessCookieName, accessToken, h.cfg.Auth.AccessTokenTTL)
	setCookie(w, h.cfg, h.cfg.Auth.RefreshCookieName, refreshToken, h.cfg.Auth.RefreshTokenTTL)
	return nil
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

func (h *AuthHandler) rotateTokens(ctx context.Context, w http.ResponseWriter, claims *utils.Claims) error {
	if err := h.tokenStore.Revoke(ctx, claims.ID); err != nil {
		return err
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
