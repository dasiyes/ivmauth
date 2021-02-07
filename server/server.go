package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
	"ivmanto.dev/ivmauth/utils"
)

// Server holds the dependencies for a HTTP server
type Server struct {
	Auth authenticating.Service
	Pks  pksrefreshing.Service

	Logger kitlog.Logger

	router chi.Router
}

// New returns a new HTTP server.
func New(au authenticating.Service, pks pksrefreshing.Service, logger kitlog.Logger) *Server {
	s := &Server{
		Auth:   au,
		Pks:    pks,
		Logger: logger,
	}

	r := chi.NewRouter()

	r.Use(accessControl)
	// TODO: Add compression and other must have middleware functions

	// Test the authentication and return the code version if successful
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		v := utils.NewVersion(0, 0, 1)
		w.Write([]byte(v.GetVersion("dev")))
	})

	// Route all authentication calls
	r.Route("/", func(r chi.Router) {
		h := authHandler{s.Auth, s.Pks, s.Logger}
		r.Mount("/v1", h.router())
	})

	r.Method("GET", "/metrics", promhttp.Handler())

	s.router = r

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

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

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	switch err {
	case ivmanto.ErrUnknownGrantType:
		w.WriteHeader(http.StatusNotFound)
	case ivmanto.ErrInvalidArgument:
		w.WriteHeader(http.StatusBadRequest)
	case authenticating.ErrClientAuth:
		w.WriteHeader(http.StatusForbidden)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
}
