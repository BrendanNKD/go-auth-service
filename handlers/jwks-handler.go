package handlers

import (
	"encoding/json"
	"net/http"

	"auth-service/middleware"
	"auth-service/utils"
)

func (h *AuthHandler) JWKSHandler(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	jwks := utils.JWKS{
		Keys: []utils.JWK{
			utils.NewRSAJWK(h.cfg.Auth.AccessTokenPublicKey, h.cfg.Auth.AccessTokenKeyID),
		},
	}

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		return middleware.NewAppError(http.StatusInternalServerError, "Could not encode JWKS", err)
	}
	return nil
}
