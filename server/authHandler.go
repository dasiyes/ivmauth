package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
)

type authHandler struct {
	aus authenticating.Service
	pks pksrefreshing.Service

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

	ctx := r.Context()
	var client ivmanto.Client

	if v := ctx.Value(Cid); v != nil {
		client, _ = v.(ivmanto.Client)
	}

	reqbody, err := h.aus.GetRequestBody(r)
	if err != nil {
		_ = level.Error(h.logger).Log("error ", err)
		ivmanto.EncodeError(context.TODO(), http.StatusBadRequest, err, w)
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
	_, _ = h.aus.RegisterNewRequest(&r.Header, reqbody, &client)

	// Validate auth request. Authenticated client's scope to consider
	at, err := h.aus.Validate(&r.Header, reqbody, h.pks, &client)
	if err != nil {
		ivmanto.EncodeError(context.TODO(), http.StatusForbidden, err, w)
		return
	}

	fmt.Printf("access token:\n\n %v;\n", at)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(at); err != nil {
		_ = h.logger.Log("error", err)
		ivmanto.EncodeError(context.TODO(), http.StatusInternalServerError, err, w)
		return
	}
}
