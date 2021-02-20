package server

import (
	"io/ioutil"
	"net/http"

	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
)

// Cid to hold on the ClientID in the request to be transfered over the request context
var Cid ivmanto.ClientID

// UID to hold the on the user ID...
var UID ivmanto.UserID

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

	// TODO: Review the middleware requirements
	r.Use(accessControl)
	// TODO: This logging is "expensive". Remove it on performance issues
	r.Use(requestsLogging(s.Logger))
	r.Use(authClients(s.Logger, s.Auth))

	// Route all authentication calls
	r.Route("/auth", func(r chi.Router) {
		h := authHandler{s.Auth, s.Pks, s.Logger}
		r.Mount("/v1", h.router())
	})

	r.Method("GET", "/version", version())
	r.Method("GET", "/metrics", promhttp.Handler())

	s.router = r

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// Response to "GET /" with the current version of the Ivmanto's auth service
func version() http.Handler {
	var ver []byte
	var err error

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ver, err = ioutil.ReadFile("version")
		if err != nil {
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(ver)
	})
}
