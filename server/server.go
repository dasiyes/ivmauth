package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dasiyes/ivmapi/pkg/config"
	"github.com/dasiyes/ivmapi/pkg/tools"
	"github.com/dasiyes/ivmsesman"
	"github.com/go-chi/chi"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dasiyes/ivmauth/core"
	"github.com/dasiyes/ivmauth/pkg/forms"
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

	// authorize end-point
	r.Route("/oauth", func(r chi.Router) {
		r.Get("/authorize", s.processAuthCode)
		r.Post("/login", s.authLogin)
		r.Route("/ui", func(r chi.Router) {
			r.Get("/login", s.userLoginForm)
		})
	})

	// Route all authentication calls
	r.Route("/auth", func(r chi.Router) {
		h := authHandler{s.Auth, s.Pks, s.Logger, s.Sm}
		r.Mount("/", h.router())
	})

	s.router = r

	return s
}

// ServeHTTP request entry point
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// [WIP] processAuthCode will handle the requests sent for authorize as initation of the AuthCode fllow with PKCE extension
func (s *Server) processAuthCode(w http.ResponseWriter, r *http.Request) {

	// Sample:
	//
	//https://authorization-server.com/authorize?
	//response_type=code
	//&client_id=H-hICOjJs8_4pxiyqud9jvxZ
	//&redirect_uri=https://www.oauth.com/playground/authorization-code-with-pkce.html
	//&scope=photo+offline_access
	//&state=ZwUAXBT9cf0btwOR
	//&code_challenge=U4wChzuCcE215Yha-Qc7ZoBc4u1rkeFHJCoQUUPcD0E
	//&code_challenge_method=S256

	var err error
	_ = level.Debug(s.Logger).Log("requestURI", r.RequestURI)

	r.URL.RawQuery, err = url.QueryUnescape(r.URL.RawQuery)
	if err != nil {
		fmt.Printf("error unescaping URL query: %q\n", err.Error())
	}

	q := r.URL.Query()

	_ = level.Debug(s.Logger).Log("response_type", q.Get("response_type"))
	_ = level.Debug(s.Logger).Log("client_id", q.Get("client_id"))
	_ = level.Debug(s.Logger).Log("redirect_uri", q.Get("redirect_uri"))
	_ = level.Debug(s.Logger).Log("scope", q.Get("scope"))
	_ = level.Debug(s.Logger).Log("state", q.Get("state"))
	_ = level.Debug(s.Logger).Log("code_challenge", q.Get("code_challenge"))
	_ = level.Debug(s.Logger).Log("code_challenge_method", q.Get("code_challenge_method"))

	var sid = strings.TrimSpace(q.Get("state"))
	var coch = strings.TrimSpace(q.Get("code_challenge"))
	var mth = strings.TrimSpace(q.Get("code_challenge_method"))

	if coch == "" || mth == "" {
		s.responseBadRequest(w, "processAuthCode", errors.New("missing mandatory code challenge or method"))
	}

	var code = tools.GenerateAuthCode(sid, coch, mth)
	if code == "" {
		s.responseUnauth(w, "processAuthCode", errors.New("error while generating the auth code"))
		return
	}

	// save the code_challenge along with the code_challenge_method and the code itself in the Session-Store (firestore)
	err = s.Sm.SaveCodeChallengeAndMethod(sid, coch, mth, code)
	if err != nil {
		s.responseUnauth(w, "processAuthCode", err)
		return
	}

	// Response in the format:
	// https://example-app.com/cb?code=AUTH_CODE_HERE&state=1234zyx

	// var wa_host = s.Config.GetSvsCfg().Host[0]
	var api_gw_host = s.Config.GetAPIGWSvcURL()
	var redirectURL = fmt.Sprintf("https://%s/oauth/ui/login?t=%s", api_gw_host, sid)

	// TODO [dev]: after the LoginSvc return TRUE for successful complete operation of user authentication - redirect to the client below...
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// [WIP] ... validate user's input credentials
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {

	headerContentTtype := r.Header.Get("Content-Type")
	// TODO: remove after debug
	_ = level.Debug(s.Logger).Log("---content-type", headerContentTtype)

	if headerContentTtype != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	r.ParseForm()

	var email = r.FormValue("email")
	var password = r.FormValue("password")

	// TODO: remove after debug
	_ = level.Debug(s.Logger).Log("email", email, "pass", password)

	// TODO [dev]: WHEN credentials are verified and user is authenticated - redirect to the client with all paramrs from method "processAuthCode"
	w.WriteHeader(200)

}

//[WIP] userLoginForm will handle the UI for users Login Form
func (s *Server) userLoginForm(w http.ResponseWriter, r *http.Request) {
	// fmt.Fprintln(w, "display the Login Form")

	var state = r.URL.Query().Get("t")
	var cid string

	cc, err := r.Cookie("c")
	if err != nil {
		_ = level.Error(s.Logger).Log("error-get-client-id", err.Error())
		cid = ""
	} else {
		cid = cc.Value
	}

	var td = ssoapp.TemplateData{
		CSRFToken: state,
		Form:      forms.New(nil),
		ClientID:  cid,
	}
	s.IvmSSO.Render(w, r, "login.page.tmpl", &td)

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
