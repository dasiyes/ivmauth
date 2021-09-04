package server

import (
	"embed"
	"io/ioutil"
	"net/http"

	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ivmanto.dev/ivmauth/authenticating"
	"ivmanto.dev/ivmauth/ivmanto"
	"ivmanto.dev/ivmauth/pksrefreshing"
)

// var fscontent *embed.FS

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
var Cid ivmanto.ClientID

// UID to hold the on the user ID...
var UID ivmanto.UserID

// Server holds the dependencies for a HTTP server
type Server struct {
	Auth    authenticating.Service
	Pks     pksrefreshing.Service
	Sm      *ivmsesman.Sesman
	Content *embed.FS
	Logger  kitlog.Logger

	router chi.Router
}

// New returns a new HTTP server.
func New(au authenticating.Service, pks pksrefreshing.Service, logger kitlog.Logger, sm *ivmsesman.Sesman, fs *embed.FS) *Server {
	s := &Server{
		Auth:    au,
		Pks:     pks,
		Sm:      sm,
		Content: fs,
		Logger:  logger,
	}

	r := chi.NewRouter()

	// TODO: Review the middleware requirements
	r.Use(accessControl)
	// TODO: This logging is "expensive". Remove it on performance issues
	r.Use(requestsLogging(s.Logger))
	r.Use(authClients(s.Logger, s.Auth))

	r.Method("GET", "/version", version())
	r.Method("GET", "/metrics", promhttp.Handler())

	fileServer := http.FileServer(http.Dir("./assets"))
	r.Method("GET", "/assets/*", http.StripPrefix("/assets/", fileServer))

	// fscontent = fs
	// r.Method("GET", "/assets/*", http.StripPrefix("/auth/v1/assets", http.FileServer(http.FS(fscontent))))

	// Route all authentication calls
	r.Route("/auth", func(r chi.Router) {
		h := authHandler{s.Auth, s.Pks, s.Content, s.Logger, s.Sm}
		r.Mount("/", h.router())
	})

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
