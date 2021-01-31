package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"

	ivmanto "ivmanto.dev/ivmauth"
	"ivmanto.dev/ivmauth/authenticating"
)

type authHandler struct {
	s      authenticating.Service
	logger kitlog.Logger
}

func (h *authHandler) router() chi.Router {
	r := chi.NewRouter()

	r.Route("/auth", func(r chi.Router) {
		r.Post("/", h.authenticateRequest)
	})

	r.Method("GET", "/docs", http.StripPrefix("/auth/v1/docs", http.FileServer(http.Dir("booking/docs"))))

	return r
}

func (h *authHandler) authenticateRequest(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	var request struct {
		GrantType string `json:"grant_type"`
		IDToken   string
		Email     string
		Password  string
		Scope     string
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.logger.Log("error", err)
		encodeError(ctx, err, w)
		return
	}

	// TODO: compose the RequestSpec below before handinding it over to Validate function
	rs := ivmanto.RequestSpec{}

	at, err := h.s.Validate(rs)
	if err != nil {
		encodeError(ctx, err, w)
		return
	}

	var response = struct {
		AccessToken ivmanto.AccessToken `json:"access_token"`
	}{
		AccessToken: at,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Log("error", err)
		encodeError(ctx, err, w)
		return
	}
}
