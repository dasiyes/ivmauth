package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
)

type authHandler struct {
	aus    authenticating.Service
	pks    pksrefreshing.Service
	logger kitlog.Logger
}

func (h *authHandler) router() chi.Router {
	r := chi.NewRouter()

	r.Route("/", func(r chi.Router) {
		r.Post("/", h.authenticateRequest)
	})

	r.Method("GET", "/docs", http.StripPrefix("/auth/v1/docs", http.FileServer(http.Dir("authenticating/docs"))))

	return r
}

func (h *authHandler) authenticateRequest(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	reqbody, err := h.aus.GetRequestBody(r)
	if err != nil {
		_ = h.logger.Log("error", err)
		encodeError(ctx, err, w)
		return
	}

	// Preliminary download JWKS for idToken validation if the x-token-type is not empty
	var tt = r.Header.Get("x-token-type")
	if tt != "" {
		go h.pks.DownloadPKSinCache(tt)
		// TODO: debug to find why it does not work
		// go h.pks.InitOIDProviders()
	}

	// ? Registering auth request
	_, _ = h.aus.RegisterNewRequest(r.Header, *reqbody)

	// Validate auth request
	at, err := h.aus.Validate(r.Header, reqbody, h.pks)
	if err != nil {
		encodeError(ctx, err, w)
		return
	}

	var response ivmanto.AccessToken = *at

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		_ = h.logger.Log("error", err)
		encodeError(ctx, err, w)
		return
	}
}
