package server

import (
	"net/http"

	"github.com/dasiyes/ivmapi/pkg/config"
	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"

	"github.com/dasiyes/ivmauth/core"
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
}

// New returns a new HTTP server.
func New(au authenticating.Service, pks pksrefreshing.Service, logger kitlog.Logger, sm *ivmsesman.Sesman, cfg config.IvmCfg) *Server {
	s := &Server{
		Auth:   au,
		Pks:    pks,
		Sm:     sm,
		Logger: logger,
		Config: cfg,
	}

	r := chi.NewRouter()

	// TODO: Review the middleware requirements
	r.Use(accessControl)
	// TODO: This logging is "expensive". Remove it on performance issues
	r.Use(requestsLogging(s.Logger))
	r.Use(authClients(s.Logger, s.Auth))

	// Handle the resources files for the Login Screen
	fileServer := http.FileServer(http.Dir("./ui/resources"))
	r.Method("GET", "/resources/*", http.StripPrefix("/resources/", fileServer))

	// authorize end-point
	r.Route("/authorize", func(r chi.Router) {
		h := authorizeHandler{s.Auth, s.Pks, s.Logger, s.Sm, s.Config}
		r.Mount("/", h.router())
	})

	// Route all authentication calls
	r.Route("/auth", func(r chi.Router) {
		h := authHandler{s.Auth, s.Pks, s.Logger, s.Sm}
		r.Mount("/", h.router())
	})

	s.router = r

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// OAuth Server error serving
// func (s *Server) serverError(w http.ResponseWriter, err error) {
// 	trace := fmt.Sprintf("[OauthServer] %s\n%s", err.Error(), debug.Stack())
// 	_ = level.Error(s.Logger).Log("AuthServer-debug-trace", trace)

// 	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
// }

// OAuth Server - unauthorized response error
// func (s *Server) unauthError(w http.ResponseWriter, err error) {
// 	w.Header().Set("Connection", "close")
// 	_ = level.Error(s.Logger).Log("AuthServer-Error", err.Error())
// 	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
// 	return
// }
