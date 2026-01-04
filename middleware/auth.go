package middleware

import (
	"context"
	"net/http"
	"strings"

	"auth-service/config"
	"auth-service/utils"
)

type contextKey string

const userClaimsKey contextKey = "userClaims"

func AuthMiddleware(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := tokenFromRequest(r, cfg.Auth.AccessCookieName)
			if token == "" {
				http.Error(w, "No token provided", http.StatusUnauthorized)
				return
			}

			claims, err := utils.ParseAccessToken(token, cfg.Auth.AccessTokenPublicKey)
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ClaimsFromContext(ctx context.Context) (*utils.Claims, bool) {
	claims, ok := ctx.Value(userClaimsKey).(*utils.Claims)
	return claims, ok
}

func ContextWithClaims(ctx context.Context, claims *utils.Claims) context.Context {
	return context.WithValue(ctx, userClaimsKey, claims)
}

func RoleMiddleware(allowedRoles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || !contains(allowedRoles, claims.Role) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func tokenFromRequest(r *http.Request, cookieName string) string {
	if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	return strings.TrimPrefix(authHeader, "Bearer ")
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
