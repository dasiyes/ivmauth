package server

import (
	"context"
	"net/http"

	kitlog "github.com/go-kit/kit/log"
	"ivmanto.dev/ivmauth/authenticating"
)

type authClientHandler struct {
	s      authenticating.Service
	logger kitlog.Logger
}

func (c *authClientHandler) authClients(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := context.Background()

		// check the whitelisted methods-paths
		if isReqWhitelisted(r) {
			h.ServeHTTP(w, r)
			return
		}
		if err := c.s.AuthenticateClient(r); err != nil {
			encodeError(ctx, authenticating.ErrClientAuth, w)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// Check the request against a whitelisted method-path pairs
func isReqWhitelisted(r *http.Request) bool {

	mr := r.Method + " " + r.URL.Path
	switch mr {
	case "GET /version":
		return true
	default:
		return false
	}
}
