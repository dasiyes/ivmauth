package server

import (
	"fmt"
	"net/http"

	"github.com/dasiyes/ivmapi/pkg/config"
	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/pkg/ssoapp"
	"github.com/dasiyes/ivmauth/svc/authenticating"
	"github.com/dasiyes/ivmauth/svc/pksrefreshing"
)

// TODO: Authorization process review against the checklist below:
// **Authorization Framework Evaluation Checklist**
// - Supports a provider-based model and lets you configure alternative authorization and role-mapping providers.
// - Supports delegating authorization and role-mapping providers to allow evaluating multiple types  of policies  in the context  of a single request.
// - Enables dynamic role evaluation to reevaluate user roles in the context of a specific action or access to some  resource.
// - Includes policy-simulation capabilities to answer the following questions: Can user X access resource Y? Who can access re- source Y?
// - Allows policy modeling in native application terminology, as opposed to generic  HTTP terms.
// - Provides PEP for all major components of the application under consideration.
// - Meets your scalability and latency requirements.

// Cid to hold on the ClientID in the request to be transfered over the request context
var Cid core.ClientID

// UID to hold the on the user ID...
var UID core.UserID

// Server holds the dependencies for a HTTP server
type Server struct {
	Auth   authenticating.Service
	Pks    pksrefreshing.Service
	Sm     *ivmsesman.Sesman
	Logger kitlog.Logger
	router chi.Router
	Config config.IvmCfg
	IvmSSO *ssoapp.IvmSSO
}

// New returns a new HTTP server.
func New(au authenticating.Service, pks pksrefreshing.Service, logger kitlog.Logger, sm *ivmsesman.Sesman, cfg config.IvmCfg, sso *ssoapp.IvmSSO) *Server {
	s := &Server{
		Auth:   au,
		Pks:    pks,
		Sm:     sm,
		Logger: logger,
		Config: cfg,
		IvmSSO: sso,
	}

	r := chi.NewRouter()

	// TODO: Review the middleware requirements
	r.Use(accessControl)
	// TODO: This logging is "expensive". Remove it on performance issues
	r.Use(requestsLogging(s.Logger))
	r.Use(authClients(s.Logger, s.Auth))

	// Handle the resources files for the Login Screen
	fileServer := http.FileServer(http.Dir("./ui/static"))
	r.Method("GET", "/static/*", http.StripPrefix("/static/", fileServer))

	// Attach instrumenting
	r.Method("GET", "/oauth/metrics", promhttp.Handler())

	// Route all authentication calls
	r.Route("/oauth", func(r chi.Router) {
		lgr := kitlog.With(s.Logger, "handler", "oauthHandler")
		h := oauthHandler{server: s, logger: lgr}
		r.Mount("/", h.router())
	})

	// Route all authentication calls
	r.Route("/auth", func(r chi.Router) {
		lgr := kitlog.With(s.Logger, "handler", "authHandler")
		h := authHandler{s.Auth, s.Pks, lgr, s.Sm}
		r.Mount("/", h.router())
	})

	s.router = r

	return s
}

// ServeHTTP request entry point
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// responseUnauth returns response status code 401 Unauthorized
func (s *Server) responseUnauth(w http.ResponseWriter, method string, err error) {
	w.Header().Set("Connection", "close")
	_ = level.Error(s.Logger).Log("handler", "oauthHandler", fmt.Sprintf("method-%s", method), err.Error())
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// responseBadRequest returns response status code 400 Bad Request
func (s *Server) responseBadRequest(w http.ResponseWriter, method string, err error) {
	w.Header().Set("Connection", "close")
	_ = level.Error(s.Logger).Log("handler", "oauthHandler", fmt.Sprintf("method-%s", method), err.Error())
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}
