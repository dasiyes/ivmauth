package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/svc/authenticating"
	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/justinas/nosurf"
)

// Handles the CORS part
func accessControl(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-TOKEN-TYPE, X-GRANT-TYPE, X-IVM-CLIENT")

		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Max-Age", "3600")
			w.WriteHeader(http.StatusNoContent)
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
				"origin", r.Header.Get("Origin"),
				"referrer", r.Header.Get("Referer"),
				"method", r.Method,
				"path", r.RequestURI,
				"remote", r.RemoteAddr,
			)
			next.ServeHTTP(w, r)
		})
	}
}

// Handles the client authentication requests
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
				switch err {
				case core.ErrBadRequest:
					core.EncodeError(context.TODO(), http.StatusBadRequest, core.ErrClientAuth, w)
				default:
					core.EncodeError(context.TODO(), http.StatusUnauthorized, core.ErrClientAuth, w)
				}
				return
			}

			Cid = rsClient.ClientID
			ctx := context.WithValue(r.Context(), Cid, *rsClient)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Create a NoSurf middleware function which uses a customized CSRF cookie with
// the Secure, Path and HttpOnly flags set.
func noSurf(next http.Handler) http.Handler {
	csrfHandler := nosurf.New(next)
	csrfHandler.SetBaseCookie(http.Cookie{
		HttpOnly: true,
		Path:     "/",
		Secure:   true,
	})

	return csrfHandler
}

// Check the request against a whitelisted method-path pairs
func isReqWhitelisted(r *http.Request) bool {

	// TODO: Move the whitelisted strings in external storage envvar? / config?
	mr := r.Method + " " + r.URL.Path
	fmt.Printf("request path: %#v;\n", mr)

	switch {
	case strings.HasPrefix(mr, "GET /.well-known/openid-configuration"):
		return true
	case strings.HasPrefix(mr, "GET /auth/version"):
		return true
	case strings.HasPrefix(mr, "GET /auth/metrics"):
		return true
	case strings.HasPrefix(mr, "GET /oauth/metrics"):
		return true
	case strings.HasPrefix(mr, "GET /oauth/token"):
		return true
	case strings.HasPrefix(mr, "GET /oauth/ui"):
		return true
	case strings.HasPrefix(mr, "GET /oauth2/v1/certs"):
		return true
	default:
		return false
	}
}
