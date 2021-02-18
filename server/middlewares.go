package server

import (
	"context"
	"net/http"

	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/ivmanto"
)

// Handles the CORS part
func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-TOKEN-TYPE, X-GRANT-TYPE, X-IVM-CLIENT")

		if r.Method == "OPTIONS" {
			return
		}

		h.ServeHTTP(w, r)
	})
}

// Handles the requests logging
func requestsLogging(lg kitlog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			_ = level.Debug(lg).Log(
				"host", r.Host,
				"method", r.Method,
				"path", r.RequestURI,
				"remote", r.RemoteAddr,
			)
			next.ServeHTTP(w, r)
		})
	}
}

// Handles the requests logging
func authClients(lg kitlog.Logger, au authenticating.Service) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// check the whitelisted methods-paths
			if isReqWhitelisted(r) {
				next.ServeHTTP(w, r)
				return
			}
			rsClient, err := au.AuthenticateClient(r)
			if err != nil {
				ivmanto.EncodeError(context.TODO(), http.StatusUnauthorized, ivmanto.ErrClientAuth, w)
				return
			}
			key := rsClient.ClientID
			val := rsClient.Scopes

			ctx := context.WithValue(r.Context(), key, val)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Check the request against a whitelisted method-path pairs
func isReqWhitelisted(r *http.Request) bool {

	// TODO: Move the whitelisted strings in external storage envvar? / config?
	mr := r.Method + " " + r.URL.Path
	switch mr {
	case "GET /version":
		return true
	default:
		return false
	}
}
